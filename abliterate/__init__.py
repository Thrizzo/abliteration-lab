"""Architecture-aware abliteration for the GLM family (GLM-Edge, GLM-4, GLM-4.xV, GLM-4.5/4.6 MoE,
GLM-5.x MoE+DSA, GLM-5-Next, legacy ChatGLM).

    python -m abliterate --model THUDM/glm-edge-4b-chat
    python -m abliterate --model zai-org/GLM-5.2 --device-map auto --skip-verify --no-ollama

Method (Arditi et al. 2024): measure the mean residual-stream difference between harmful and harmless
prompts per layer, scan which layer's direction best removes refusals when projected out at inference
time, then project that direction out of every weight matrix that writes into the residual stream
(token embedding, attention output projection, every MLP output projection incl. MoE experts).
With --layers (or --combine in the scan) the directions of several layers are removed together: the subspace
they span, through an orthonormal basis (edit.basis).
"""
