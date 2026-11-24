"""Data tooling for the n8n pentest copilot: writeup ingestion for retrieval (RAG) and QLoRA training data.

    copilot.sources      find and read writeups; the first folder sets the source tag (htb, blog, engagement, pwk)
    copilot.scrub        per-source redaction (client data in engagement notes, hard secrets everywhere)
    copilot.chunk        markdown-aware chunking that keeps commands with the prose explaining them
    copilot.ingest       CLI: scrub -> chunk -> embed (Ollama) -> Qdrant, in the schema n8n's Qdrant node reads
    copilot.pairs        CLI: writeups -> (state -> next command) JSONL in the operator's JSON contract
    copilot.train_qlora  CLI: QLoRA on the read-side matrices only (derived from abliterate.arch), then merge
    copilot.eval_operator  CLI: score operator suggestions (JSON validity, tool match, similarity, policy pass)
"""
