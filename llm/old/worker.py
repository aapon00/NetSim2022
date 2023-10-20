import requests
import openai
from models import NetworkPacketList, NetworkPacket

def get_gpt_completion(**kwargs):
    response = openai.ChatCompletion.create(**kwargs)
    return response.choices[0]

def get_summary(
        in_packets: NetworkPacketList,
):
    messages=[
        {"role": "user", "content": "You are a network analyst. Analyze the following network packets and describe their contents, behavior, and rules, in a few sentences. Describe the overall trend of the network traffic, not details of individual packets."},
        {
            "role": "assistant",
            "content": "response"
        },
        {"role": "user", "content": NetworkPacketList(packets=in_packets).json()},
    ]
    
    response = get_gpt_completion(
        model="gpt-3.5-turbo",
        messages=messages,
        max_tokens=500,
    )
    return response.message.content

def get_synthetic_packets(
        in_packets: NetworkPacketList,
        summary: str,
):
    response = get_gpt_completion(
            model="gpt-3.5-turbo-0613",
            messages=[
            {"role": "user", "content": "You are a network analyst. Analyze the following network packets and return synthetic new packets based on the summary that would follow the same patterns and rules, but with different timestamps, traffic details, IP addresses, etc that model, but are not an exact copy of, the source data."},
            {"role": "user", "content": NetworkPacketList(packets=in_packets).json()},
            {"role": "user", "content": summary},
            ],
            functions=[
                {
                "name": "returnListOfPackets",
                "description": "Return a list of generated packets",
                "parameters": NetworkPacketList.model_json_schema()
                }
            ],
            function_call={"name": "returnListOfPackets"}
    )
    print(response)
    return response

def get_summary_and_similar(
        in_packets: NetworkPacketList,
):
    summary = get_summary(in_packets)
    return get_synthetic_packets(in_packets, summary)