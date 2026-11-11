# Offgrid Studio

A local-first browser workspace for GGUF language models, powered by wllama / llama.cpp WebAssembly. Run `npm install` and `npm run dev` to develop, or `npm run build` for a static deployment.

Choose one or more GGUF model files, or supply a direct, CORS-enabled GGUF URL. The model and inference run in the browser; URL downloads are fetched from the model host. Models need enough memory and compatible browser support; large files may need splitting. Models are unloaded on reload. Chat stays in the current tab and is not persisted.

ONNX files are not supported yet: arbitrary ONNX graphs require model-specific tokenization, configuration and generation logic. This app does not upload them or pretend to run them. There is no service-imposed usage limit, but inference is limited by hardware, browser resources and model compatibility.
