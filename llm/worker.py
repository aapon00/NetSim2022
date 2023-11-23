import requests
import openai
from classes import NetworkPacketList, NetworkPacket

# Langchain - General
from langchain.chat_models import ChatOpenAI
from langchain.llms import LlamaCpp, VertexAI, Cohere  # LLMs
from langchain.schema import AIMessage, HumanMessage, SystemMessage  # Schema
from langchain.prompts import PromptTemplate  # General Prompt Template
from langchain.chains import LLMChain  # LLM Chains

# Langchain - Prompts
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
    HumanMessagePromptTemplate,
)

# Langchain - Callbacks
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler

from redis import Redis
from rq import Worker

# Set up models
models = {
    "gpt-35": {
        "name": "GPT-3.5-Turbo",
        "modelClass": ChatOpenAI,
        "modelArgs": {"temperature": 0.5, "model": "gpt-3.5-turbo"},
        "type": "chat",
    },
    "gpt-4": {
        "name": "GPT-4",
        "modelClass": ChatOpenAI,
        "modelArgs": {"temperature": 0.5, "model": "gpt-4"},
        "type": "chat",
    },
    "gpt-4-turbo": {
        "name": "GPT-4-Turbo",
        "modelClass": ChatOpenAI,
        "modelArgs": {"temperature": 0.5, "model": "gpt-4-1106-preview", "openai_api_key": "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"},
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


def run_model(in_packets: NetworkPacketList, prompt_obj: str, model: str):
    # Create the model based on its class and arguments
    model = models[model]
    model["model"] = model["modelClass"](**model["modelArgs"])
    prompt = prompt_obj["prompt"]

    # Switch based on if it is a chat or completion model

    if model["type"] == "chat":
        # Set up chat prompt
        system_message = SystemMessage(
            content=prompt,
        )
        human_message = HumanMessagePromptTemplate.from_template(
            "Please create new packets based on this network traffic data: {input}"
        )

        chat_prompt = ChatPromptTemplate.from_messages([system_message, human_message])
        output = model["model"](
            chat_prompt.format_prompt(input=in_packets).to_messages()
        ).content

        return output

    elif model["type"] == "completion":
        # Set up completion prompt
        completion_prompt = PromptTemplate(
            template="""{prompt}
            Input: {input}
            Output: """,
            input_variables=["prompt", "input"],
        )
        chain = LLMChain(llm=model["model"], prompt=completion_prompt)
        output = chain.predict(
            prompt=prompt,
            input=in_packets,
        )

        return output

    else:
        raise Exception("Model type not supported")