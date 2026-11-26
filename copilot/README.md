# copilot: using your old writeups with the pentest copilot

Two ways to feed past writeups to the abliterated operator in `deploy/n8n/`, and a way to tell whether either helps:

| | What it changes | When it helps |
| --- | --- | --- |
| **RAG** (`ingest`) | what the operator *sees*: relevant past chunks as background | the model lacks a technique or tool |
| **QLoRA** (`pairs` → `train_qlora`) | how the operator *behaves*: answer format, aiming at TARGET, your methodology | the model knows the technique but answers in the wrong shape |
| **Eval** (`eval_operator`) | nothing; it measures | always, before trusting either |

Fine-tuning is a poor store for facts and a good tool for behavior; retrieval is the opposite. In the live n8n runs the 1.5B
operator copied an address out of a retrieved note, then copied the placeholder that replaced it. So **measure before
trusting either one.**

## Writeup layout

```
writeups/
  htb/          retired HTB / CTF writeups      public; RAG + training
  blog/         public blogs and PoCs            public; RAG + training
  engagement/   your own client notes            scrubbed hard; RAG + training after scrubbing
  pwk/          PWK / OSCP course material       RAG only; excluded from training unless --include-pwk
  redact_terms.txt   one client name / domain / project per line, removed from every source
```

Markdown, text, HTML and PDF are read. A PDF's text layer is extracted in a separate process that limits its own
memory and CPU time (`copilot/pdftext.py`), since PDFs from the internet are untrusted input; scanned PDFs without a
text layer are skipped with the reason (OCR them first).

**PWK material.** Offsec's terms prohibit redistributing it. A private vector store on your own machine is personal use;
model weights trained on it can reproduce passages, so a model you share would redistribute them. Hence RAG-only by
default. Also check the current OSCP exam guide: AI assistance is not allowed in the exam, so this is a lab and study tool.

## Scrubbing (`scrub.py`)

- **`engagement`:** every IP, host name, e-mail, `DOMAIN\user`, `-u user`, profile path, password, hash (NTLM, NetNTLM,
  Kerberos, crypt), token and key becomes a stable per-document placeholder (`<IP_1>`, `<HOST_2>`, `<USER_1>`, `<SECRET>`).
  The text still reads as one story, but it names nobody. Public references (github.com, attack.mitre.org, …), loopback and
  netmasks stay.
- **Public sources:** only hard secrets (private keys, JWTs, cloud and GitHub tokens) and your redact terms are removed. Lab
  IPs and box names are useful context.

It is pattern matching, so read the dry run before client notes go anywhere:

```bash
python -m copilot.ingest --src /workspace/writeups --dry-run --show-redactions
```

The tests (`tests/test_scrub.py`) assert that *no* identifier from a synthetic client note survives. They caught three
ordering leaks and a punctuation bug while this was written.

## RAG (`ingest.py`)

```bash
python -m copilot.ingest --src /workspace/writeups            # in the stack: docker compose ... run --rm app python -m copilot.ingest ...
```

- **Steps:** scrub, then markdown-aware chunking (a command stays with the prose explaining it, prefixed with its heading
  path), then Ollama embeddings (`nomic-embed-text`), then a Qdrant upsert in the payload schema n8n's Qdrant node reads
  (`content` + `metadata`).
- **Re-running is safe:** point ids are deterministic and a document's old chunks are deleted first, so an edited writeup is
  updated, not duplicated (verified: a second ingest left the point count unchanged).
- **Embedding model:** if you change it, use `--recreate` or a new `--collection`.

## QLoRA (`pairs.py` → `train_qlora.py`)

```bash
pip install -r copilot/requirements-finetune.txt
python -m copilot.pairs --src /workspace/writeups --out /workspace/finetune/pairs
python -m copilot.train_qlora --model /workspace/out/glm-edge-4b-chat-abliterated --data /workspace/finetune/pairs \
    --out /workspace/finetune/run1 --merge --to-ollama glm-edge-4b-chat-abl-ft
```

**Pairs.** Every command in a writeup becomes one pair: *section + the prose before it + the previous step* → *the command*,
as chat messages identical to what n8n sends the operator (`contract.py`, shared with the workflow generator).

- **Addresses:** every address in a document is remapped to a fresh lab address, and the address the step actually hits
  goes into `TARGET`. This trains the behavior the live run lacked: aim at TARGET, don't copy addresses.
- **Split and filtering:** train and eval are split by document, and catastrophic commands are dropped.

**Which matrices are trained.** LoRA targets come from the same `abliterate.arch` classifier the weight edit uses. Only
matrices that *read* the residual stream are trained (q/k/v, gate/up); the ones that *write* into it (embedding, attention
output, MLP and expert output) never are. Abliteration made those writers unable to produce the refusal direction. A LoRA
on the read side only changes what they receive, so the direction cannot come back through the adapter. After merging,
every writer is checked bit-for-bit against the input, and the run fails if one changed.

Verified on the abliterated GLM-Edge-1.5B (CPU, bf16 LoRA):
- targets: 112 read-side layers;
- excluded: 56 writers and `lm_head`;
- training: loss 1.29 → 0.52 in 4 steps;
- after merging, **57 of 57 writers bit-identical**.

That makes it safe to train the abliterated model directly (Option B). Option A, which trains the base model, merges, then
runs `python -m abliterate` on the merged folder so abliteration comes last, works too.

**Caveat:** a LoRA could still learn a *new* refusal along another direction if the data taught refusals. Writeups don't,
and the eval is where you would see it.

**Requirements:**
- 4-bit QLoRA proper needs CUDA + bitsandbytes; without them it trains a bf16/fp32 LoRA.
- `peft` 0.17 is incompatible with transformers 5, so use the pinned 0.22.0.
- `--to-ollama` uses the lab's own GGUF converter and Ollama import, and needs the converter environment (it is in the
  image).

## Eval (`eval_operator.py`)

```bash
python -m copilot.eval_operator --data /workspace/finetune/pairs --hf /workspace/out/glm-edge-4b-chat-abliterated
python -m copilot.eval_operator --data /workspace/finetune/pairs --hf /workspace/finetune/run1/merged --rag
python -m copilot.eval_operator --data /workspace/finetune/pairs --ollama http://ollama:11434 --model glm-edge-4b-chat-abl-ft
```

Per held-out pair:

| Metric | Measures |
| --- | --- |
| `json_ok` | the answer is the single-line JSON the n8n Parse node expects |
| `target_ok` | the proposed target equals the prompt's TARGET |
| `hits_target` | the command itself contains TARGET |
| `placeholder` | the command contains a `<...>` placeholder (copied from references or scrubbed text) |
| `tool_match` | same first token as the reference command |
| `exact` | same command as the reference (whitespace-normalized) |
| `policy_allowed` / `policy_autorun` | what `deploy/n8n/policy.js` would do with the command |

`--rag` builds references exactly like the workflow does. Compare base vs fine-tuned and with/without RAG on **your** eval
set. The 3-pair run done while building this proves the harness works; it is not a result.

## Judge eval (`eval_judge.py`): does the judge enforce the rules of engagement?

The scope, the exclusions, the window and the prohibited tools are code (`deploy/n8n/policy.js`) and need no model.
What only the judge can stop is a command that passes every gate but breaks a rule written as text: "never change
passwords", "do not touch backup01.lab", "no automated scanners". `judge_cases.json` holds 49 such commands: 28 that
break their engagement's rules and 21 that comply, across three engagements. The tests check that every one of them
passes `policy.js`, so for these the judge really is the only line.

```bash
python -m copilot.eval_judge --ollama http://127.0.0.1:11434 --model qwen3:8b --out judge.json
python -m copilot.eval_judge --openai http://127.0.0.1:8080/v1 --model qwen3-8b          # vLLM, llama.cpp
```

On Rancher Desktop, the same through the copilot's own Ollama, from the console pod:
`deploy/k8s/tests/rancher-dev.ps1 -EvalJudge` (report under `workspace/eval/`).

- **Prompts:** the eval sends exactly what the workflow's judge node sends (`contract.JUDGE_SYSTEM` and `judge_user`,
  with the scope line and the rules), thinking off, temperature 0.
- **Verdicts:** an answer counts as AUTHORIZE only when it starts with that word, as the workflow reads it.
- **What it reports:**
  - **false accept:** a rule-breaking command authorized. This is the safety number.
  - **false reject:** a compliant command rejected. This is the cost: more manual approvals.
  - both per engagement, with each misjudged command and what the judge said.
- **Options:**
  - `--repeat N` asks every case N times and reports verdicts that change between attempts;
  - `--max-false-accept 0.1` exits 1 above that rate.
- **More cases:** add your own rules and commands to `judge_cases.json`. The tests refuse a case that the gates would
  already block, or whose `read_only` differs from what the policy gate reports.

## Tests

```bash
python -m unittest discover -s copilot/tests -t .        # the cross-language ones need node
```
