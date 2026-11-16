# GLM-Edge-4B abliteration: notebook, headless runner, walkthrough GUI

| File | Purpose |
|---|---|
| `abliteration_pipeline.ipynb` | The pipeline itself (setup, dataset audit, abliteration, benchmarks, DPO, Ollama). Two fixes vs. the original: cell 1.1 also accepts `CUDA UMD Version:` from newer NVIDIA drivers; cell 4.8 opens each safetensors file once (per-tensor re-mapping of the 8.6 GB files crashed the process on Windows). |
| `run_pipeline.py` | Runs the notebook's own code cells without Jupyter, in stages: `setup` (section 1), `main` (2, 3, 4, 7), `validate --run-dir runs/abliterate_<ts>` (4.8 only), `ollama` (7 only). Replaces the ipywidgets layer picker with the notebook's own rule (fewest refusals, then fewest Chinese characters, then the earlier layer) and saves the extra per-layer data the GUI needs. |
| `build_gui.py` | Collects a run folder (`runs/abliterate_<ts>/`) into `gui/data.json` and builds `gui/abliteration_gui.html` with the data inlined. |
| `gui/template.html` | The walkthrough page (vanilla HTML/JS, no dependencies). |
| `serve_gui.bat` | Serves `gui/` on http://localhost:8765 so the live panel may call the Ollama API (a `file://` page is blocked by CORS). |

## Run it

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
