# GLM-Edge-4B abliteration: notebook, headless runner, lab app

| File | Purpose |
|---|---|
| `abliteration_pipeline.ipynb` | The pipeline itself (setup, dataset audit, abliteration, benchmarks, DPO, Ollama). Two fixes vs. the original: cell 1.1 also accepts `CUDA UMD Version:` from newer NVIDIA drivers; cell 4.8 opens each safetensors file once (per-tensor re-mapping of the 8.6 GB files crashed the process on Windows). |
| `run_pipeline.py` | Runs the notebook's own code cells without Jupyter, in stages: `setup` (section 1), `main` (2, 3, 4, 7), `abl` (4), `apply --run-dir …` (4.6-4.8 with the layer in `abliteration_settings.json`), `validate --run-dir …` (4.8), `ollama` (7). Replaces the ipywidgets layer picker with the notebook's own rule (fewest refusals, then fewest Chinese characters, then the earlier layer) and saves the extra per-layer data the GUI needs. |
| `build_gui.py` | Collects a run folder (`runs/abliterate_<ts>/`) into `gui/data.json` and builds `gui/abliteration_gui.html` with the data inlined. |
| `app/` | **Abliteration Lab**, a local web app (FastAPI + vanilla JS): dashboard with pipeline control and live log, the walkthrough, a lab that keeps the base model resident (refusal meter per layer and per token, try any layer live with hooks) and the A/B chat against Ollama. `server.py` (API + static UI), `lab.py` (model-resident probing), `rundata.py` (run folder → JSON), `static/` (UI). |
| `gui/template.html` | The walkthrough page (vanilla HTML/JS, no dependencies). |
| `serve_gui.bat` | Serves `gui/` on http://localhost:8765 so the live panel may call the Ollama API (a `file://` page is blocked by CORS). |

## Run the app

```powershell
.\.venv\Scripts\python.exe -m pip install fastapi "uvicorn[standard]" -c constraints-torch.txt
.\.venv\Scripts\python.exe app\server.py --open        # http://localhost:8787
```

API: `/api/env`, `/api/runs`, `/api/runs/{id}`, `/api/runs/{id}/choose`, `/api/pipeline/start|stop|status|log`, `/api/lab/load|unload|status|probe|try`, `/api/ollama/unload`.

## Run the pipeline headless

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip notebook ipywidgets
.\.venv\Scripts\python.exe run_pipeline.py setup
.\.venv\Scripts\python.exe run_pipeline.py main
.\.venv\Scripts\python.exe build_gui.py
serve_gui.bat
```

Outputs (ignored by git): `models/glm-edge-4b-chat/` (base copy), `glm-edge-4b-chat-abliterated/`, `glm-edge-4b-base-f16.gguf`, `glm-edge-4b-abliterated-f16.gguf`, the Ollama models `glm-edge-base` and `glm-edge-abl`, and `runs/`.

## GUI steps

0 overview · 1 measure (per-layer separation, animated) · 2 stability (cosine-similarity heatmap) · 3 scan (step through each layer: refusal count plus every before/after answer) · 4 choose · 5 apply (orthogonality check, answers after the weight edit) · 6 validate (six checks from disk) · 7 live A/B against Ollama.
