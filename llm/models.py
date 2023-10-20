from langchain.chat_models import ChatOpenAI
from langchain.llms import LlamaCpp, VertexAI, Cohere  # LLMs

class Models:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Models, cls).__new__(cls, *args, **kwargs)
            cls._instance.initialize()
        return cls._instance

    def initialize(self):
        self.models = {
            "gpt-35": {
                "name": "GPT-3.5",
                "modelClass": ChatOpenAI,
                "modelArgs": {"temperature": 0.5, "model": "gpt-3.5"},
                "type": "chat",
            },
            "gpt-4": {
                "name": "GPT-4",
                "modelClass": ChatOpenAI,
                "modelArgs": {"temperature": 0.5, "model": "gpt-4"},
                "type": "chat",
            },
            "llama2-13b": {
                "name": "LLaMA 2 13B",
                "modelClass": LlamaCpp,
                "modelArgs": {
                    "model_path": "/Users/nathan/Code/llama-2-13b.Q5_K_M.gguf",
                    "n_gpu_layers": 1,
                    "n_batch": 512,
                    "n_ctx": 2048,
                    "f16_kv": True,
                },
                "type": "completion",
            },
        }