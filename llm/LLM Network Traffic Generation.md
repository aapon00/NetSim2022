# Introduction

The goal of the study is to explore the use of large language models (LLMs) to synthesize network traffic that retains the essential characteristics of real-world data while introducing controlled variations. Specifically, we intend to use large language models to directly generate new data, as opposed to having them generate code or instructions to generate new data.

# Methodology

## Data Acquisition

We used a sample of network traffic from CAIDA sourced from Gourish's earlier work (`Box/AY22_23_Synthetic_Data_Generation/pcap_to_csv/pcap_4_all_csv/4_1.csv`) as the primary data set.

## Data Cleaning & Preparation

We imported the data with `pandas`, converting the packets to objects with the following fields:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* Length
* Payload

## Model Setup & Usage

### Prompts

We generated a set of 32 prompts, both by hand and with AI assistance, that describe different techniques that one may use to study network traffic.

#### Examples

> Let's take this step by step. First, describe the most frequent packet types you see. Second, identify the most common source and destination IPs. Finally, generate new packets that maintain these general characteristics but with different payloads or flags.

> Imagine you're part of a red team exercise. What characteristics in the network traffic would you consider normal? Generate new packets that blend in with the normal traffic but with slight differences.
>
### Input

Models were provided packets as a string representation of the object, including all the fields mentioned above. Depending on the available context window of the model, the amount of input packets varied from as few as 10 to as many as 500. For example:

#### Example

```
[NetworkPacket(time=0.0, src_ip='59.166.0.8', dst_ip='149.171.126.2', src_port=24272, dst_port=80, protocol='TCP', length=68, payload='24272  >  80 [ACK] Seq=1 Ack=1 Win=34752 Len=0 TSval=4000192673 TSecr=4000176622', conversationID=None), NetworkPacket(time=9e-06, src_ip='59.166.0.8', dst_ip='149.171.126.2', src_port=24272, dst_port=80, protocol='TCP', length=68, payload='[TCP Dup ACK 1#1] 24272  >  80 [ACK] Seq=1 Ack=1 Win=34752 Len=0 TSval=4000192673 TSecr=4000176622', conversationID=None), NetworkPacket(time=0.000174, src_ip='149.171.126.2', dst_ip='59.166.0.8', src_port=80, dst_port=24272, protocol='TCP', length=1516, payload='80  >  24272 [PS', conversationID=None) [continued...] ]
```

### Model Setup

#### Chat Models

We utilized three models from OpenAI: GPT-3.5-turbo, GPT-4, and GPT-4-turbo (specifically, gpt-4-1106-preview). All chat completions were generated using the API, using the following structure:

> System Message: {prompt}
> Human Message: Please create new packets based on this network traffic data: {input}

The choice of these models was influenced by their proven capability in understanding and generating complex data patterns. Originally, we had planned to also use PaLM 2 and Cohere models, but ran into difficulty setting up billing for these providers.

#### Completion Models

We tested Meta's LLaMA 2 13B model, generating completions using `llama.cpp` on a MacBookPro18,3 with 10-core Apple M1 Pro.

> {prompt}
> Input: {input}
> Output:

### Model Calling

We utilized Redis and the associated Python library `rq` to schedule model calls and store generated completions in a scalable and persistent manner. We added multiple jobs to the queue for each combination of prompt and model. Worker threads would accept a job and either call the relevant API or run the completion locally before saving the result to the Redis store. After all jobs completed, we fetched the job data back out from the Redis store to a `pandas` DataFrame.

### Parsing

We used regular expressions to search for the `NetworkPacket(` string in the response, and parsed the data in the same format that it was output in. If no packets could be parsed, we initialized that response with an empty list.

## Statistics

Our analysis involved an evaluation of both the input and the synthesized network packets. We developed several functions to extract key metrics from the packets, which helped us compare the original and generated data. The metrics included:

| Metric                        | Description                                                  |
|-------------------------------|--------------------------------------------------------------|
| Packet Count                  | Total number of packets in a given sample.                   |
| Average Conversation Length   | Mean number of packets exchanged in a conversation.          |
| Time Delta                    | Total duration covered by the packet sequence in the sample. |
| Unique IPs and Ports          | Count of distinct IP addresses and ports used in the traffic.|
| Average Payload Length        | Mean length of packet payloads.                              |
| Average Inter-Arrival Time    | Mean time between successive packet arrivals.                |

By applying these functions to both the input and the parsed (synthesized) packets, we derived several key delta metrics:

| Delta Metric                        | Description                                                          |
|-------------------------------------|----------------------------------------------------------------------|
| Average Conversation Length Delta   | Difference in average conversation length between original and synthesized traffic. |
| Time Delta Delta                    | Difference in the time spans covered by the original and synthesized traffic.        |
| Unique IPs and Ports Delta          | Difference in the diversity of IPs and ports between original and synthesized traffic. |
| Average Payload Length Delta        | Difference in average payload length between original and synthesized traffic.        |
| Average Inter-Arrival Time Delta    | Difference in average inter-arrival times between original and synthesized traffic.   |

### Statistical Scoring

We developed a 'Summary Score' for each synthesized dataset. This score was calculated as the average of the absolute z-scores for each delta metric. The z-score, a statistical measure, indicated how far and in what direction each delta deviated from the dataset's mean, normalized by the standard deviation. So a lower summary score suggests a closer resemblance between the synthesized and original traffic.

# Results

Overall, we synthesized 1755 output data streams, of which 837 had at least one parseable packet in the response.

## Example Data

**Completions Generated by Model**

| Model | Completions Generated |
| ---- | ---- |
| gpt-4-turbo | 1094 |
| llama2-13b | 329 |
| gpt-3.5-turbo | 167 |
| gpt-4 | 165 |
| **Total** | **1755** |

This is how many completions were generated per model. GPT-4 was utilized the least because it was not cost effective.

**Average Parsed Packets by Model**

| Model | Average of Parsed Packets |
| ---- | ---- |
| gpt-35 | 9.390909091 |
| gpt-4 | 7.806060606 |
| gpt-4-turbo | 5.185595568 |
| llama2-13b | 1.009950249 |

On average, this is how many packets were generated per model, when excluding empty responses.

**Counts of Inter Arrival Time (Parsed)**

| Average Inter Arrival Time (Parsed) | Count of Average Inter Arrival Time (Parsed) |
| ---- | ---- |
| 0 | 1199 |
| 0.000331 | 133 |
| 0.001 | 59 |
| 0.00001 | 30 |
| 0.005216 | 12 |
| 0.000331111 | 12 |
| 0.020406 | 9 |
| **Others** | **301** |

This is how many responses were generated with any particular average inter arrival time.

## Raw Data

The raw results are available for analysis in the project directory, under `data/results.xlsx`.

## Observations

* Some metrics, like inter-arrival time or time delta, have common values among many outputs; for example, 59 completions had an average IAT of 0.001 seconds. This may imply a preference from the model to utilize some values over others when random or pseudorandom data is needed.
* All three of the OpenAI models performed significantly better than Llama 2 13B, which often attempted to write (rarely correct) Python code to generate the packets instead of directly generating them. Although OpenAI models were more successful, their failure mode was still, most commonly, by generating Python code instead of actual packet representations.
* Even when 500+ packets were passed as input, no system generated more than 50 packets of output data. This seems insufficient for practical uses, though it may be mitigated by asking the model to "continue generating".
 	* This is similar in nature to other model behaviors that have been described as "laziness" (see <https://twitter.com/ChatGPTapp/status/1732979491071549792?s=20>).

# Future Work

## More Models

Testing more models (such as Anthropic's Claude, Inflection's Pi, Google's existing PaLM 2 or upcoming Gemini, fine-tunes of LLaMa) may produce a more comprehensive picture of the LLM landscape. Some of these require setting up billing or reverse-engineering a web application to access an API, or significant amounts of GPU memory.

## More Data Diversity

Although we ran a total of 1755 times, a significant amount of these were with a limited data set (due to small context windows) of the first 10-50 packets of `4_1.csv`. Working with a more representative (and larger) set selected from the entire file may produce more useful results.

## Better Stats

The existing techniques for evaluating a packet or packet list's similarity to the input are not well constructed, and oftentimes result in misleading results. Although it is true that a z-score of exactly 0 implies "average" data, this is not always what we want, and moreover, averaging z-scores assigns equal "weight" to all measured statistics. I propose that a more formal method for evaluating the quality of output be developed.

## CTranslate2

CTranslate2 is a C++/Python library for efficient transformer model inference. In some cases, it has been shown to be 2-4x as fast and memory efficient as existing inference tools. By incorporating this library, potentially in addition to quantized models, we may allow us to use models that would not otherwise fit on our hardware (such as Llama 2 70B, which requires 140GB of memory pre-quantization).

## QLoRA

It may be possible to use QLoRA or similar techniques to tune these models ourselves for improved performance on network data generation tasks. One of the key reasons we didn't pursue this approach to begin with is that it requires training data (what would a "good" response even look like here?)

# Directory Structure

| File | Description |
| ---- | ---- |
| Makefile | Contains `llama` and `gpt` targets, which allowed us to quickly start new `rq` worker threads with the appropriate environment variable set. |
| classes.py | Data models for a network packet and network packet list. |
| **data/** | Input and output data. |
| ├── 4_1.csv | Input packets. |
| ├── output.json | Input and output data for each model completion, as JSON. |
| ├── output.csv | Input and output data for each model completion, as CSV. |
| ├── prompts.json | Set of 30 prompts that were used as input. |
| ├── results.xlsx | Input and output data for each model completion, and derived statistics, in XLSX. |
| models.py | List of large language models. |
| new-network-gen.ipynb | **Primary notebook for this project**. |
| **old/** | Old data from the early stages of the project. |
| ├── arthur.ipynb | Notebook that used Arthur Bench and TruLens to evaluate completions by different models. |
| ├── default.sqlite | Database used by Arthur Bench or TruLens. |
| ├── llm_network.ipynb | First notebook that was used for this project. Contains no evaluation methods, just calls OpenAI. |
| ├── random_scorer.py | Test "scorer" that would randomly evaluate different completions. |
| └── worker.py | Old worker that used OpenAI's API directly instead of LangChain. |
| palmetto-llm.md | Guide for novices to run LLMs on Palmetto. |
| worker.py | Worker script that `rq` workers used to create completions. |

# References

* <https://kubito.dev/posts/llama-cpp-linux-nvidia/>
* <https://github.com/clemsonciti/palmetto-examples/tree/master/Job-arrays>
* <https://cdn.openai.com/papers/gpt-4.pdf>
* <https://cdn.openai.com/papers/gpt-4-system-card.pdf>
* <https://scontent-atl3-2.xx.fbcdn.net/v/t39.2365-6/10000000_662098952474184_2584067087619170692_n.pdf?_nc_cat=105&ccb=1-7&_nc_sid=3c67a6&_nc_ohc=sv_RQgqDkdAAX93AMJu&_nc_ht=scontent-atl3-2.xx&oh=00_AfD8Sl6l07-z7ETIO5sUNF9BRwBOx55VsWUH6ArsUwiX2w&oe=65A5C63F>
* <https://twitter.com/ChatGPTapp/status/1732979491071549792?s=20>
* <https://github.com/OpenNMT/CTranslate2>
* <https://github.com/artidoro/qlora>

# Appendix

## Prompts

| Name                      | Prompt                                                                                                                                                   |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Essential Features        | Examine the network traffic and identify the essential features like packet size, source/destination IPs, and protocols used. Generate new packets that maintain these essential features while introducing minor variations. |
| Modify Payload            | Look at the network traffic, focusing particularly on the payload of the packets. Generate new packets that have similar but not identical payloads while keeping other packet attributes constant. |
| Timing Analysis           | Observe the timing intervals between packets in the network traffic. Create new packets that follow a similar timing pattern but with slight alterations. |
| Burst Analysis            | Identify any bursts or patterns of high-activity in the network traffic. Generate new packets that mimic this high-activity behavior but are not exact replicas. |
| Anonymized Retransmission | Review the network traffic and identify any packets that can be anonymized without losing their core characteristics. Generate new packets that are similar but anonymized. |
| Protocol Consistency      | Focus on the protocols being used in the network traffic. Create new packets that use the same protocols but have different source and destination IPs. |
| Noise Addition            | Examine the network traffic, then generate new packets that are similar in structure and content but include slight noise or variations to make them unique. |
| Sequence Reconstruction   | Observe the sequence of packets in the network traffic. Generate a new sequence that mirrors the original in terms of flow and type of packets but differs in specific details. |
| Multi-layer Analysis      | Perform a multi-layer analysis of the network traffic, looking at both transport and application layers. Generate new packets that are consistent at each layer but include minor differences. |
| IP Jitter                 | Analyze the source and destination IPs in the network traffic. Generate new packets that maintain a similar IP range but use different specific addresses. |
| Payload Pattern           | Focus on the payloads within the packet data. Identify recurring byte patterns or text strings. Generate new packets with similar but slightly altered payloads. |
| Priority Traffic          | Identify packets that seem to be prioritized based on their QoS (Quality of Service) fields. Generate new packets that follow the same QoS settings but vary in other dimensions. |
| Header Analysis           | Concentrate solely on the packet headers. What fields are most commonly used or modified? Generate new packets that have similar header settings but different content. |
| Traffic Flow              | Identify patterns in the traffic flow, such as packet rates between specific IP addresses. Generate new packets that mimic this flow but come from different IPs or ports. |
| Deep Dive                 | Perform a deep dive into a single session or connection within the network traffic. Generate new packets that could plausibly be part of the same session but aren't exact replicas. |
| Frequency Analysis        | Identify the frequency of each packet type, IP address, and port number. Generate new packets that maintain the same frequency distribution but with slight variations in the packet details. |
| Geographic Trends         | If applicable, identify any geographic trends in the IP addresses. Generate new packets that follow these trends but originate from different but geographically similar locations. |
| Multi-Protocol            | Analyze the use of multiple protocols in the traffic. Generate new packets that switch between these protocols while maintaining the general characteristics of each. |
| Random Sampling           | Select a random sample of packets from the network traffic. Analyze their common characteristics and generate new packets that could fit within this sample. |
| Temporal Patterns         | Focus on temporal patterns like the time-to-live (TTL) values or timestamp options in the packets. Generate new packets that share these temporal patterns but vary in other aspects. |
| Detailed Analysis         | Analyze the network traffic in detail. Identify recurring patterns and behaviors. Then, generate new packets that adhere to these patterns but introduce subtle variations. |
| Red Team                  | Imagine you're part of a red team exercise. What characteristics in the network traffic would you consider normal? Generate new packets that blend in with the normal traffic but with slight differences. |
| Sequential                | Let's take this step by step. First, describe the most frequent packet types you see. Second, identify the most common source and destination IPs. Finally, generate new packets that maintain these general characteristics but with different payloads or flags. |
| Summarize and Replicate   | Summarize the network traffic, focusing on the packet sizes, header fields, and payload content. After summarizing, generate new packets that are similar in these dimensions but not identical. |
| Attribute-Based           | List the top attributes (such as IP addresses, ports, protocols) that stand out in the network traffic. Generate new packets that share these attributes but have different checksums, sequence numbers, or flags. |
| Time-based Analysis       | Look at the network traffic and identify how the packet rate changes over time. Generate new packets that simulate a similar time-based pattern but with different content. |
| Anomaly Analysis          | Identify any anomalies or outliers in the network traffic. Then generate new packets that would blend in with the normal traffic but have some differences that make them slightly anomalous. |
| Protocol Specific         | Focus on a particular protocol present in the network traffic. What are the unique characteristics of packets using this protocol? Generate new packets that are consistent with this protocol but differ in some parameters. |
| Signature-Based           | Identify common signatures or patterns that stand out in the network traffic. Generate new packets that mimic these signatures but with slight alterations. |
| Traffic Behavior          | Describe the behavior of the network traffic, such as periods of high or low activity, bursts of specific packet types, or recurring sequences. Generate new packets that mimic this behavior but with unique alterations. |
| Haiku                     | Write a haiku to summarize the network traffic dump. Then, create new packets in poetic form. |
| Dialogue                  | Imagine a conversation between Alan Turing and Ada Lovelace discussing this network traffic dump. What would they say to each other? Generate new packets that reflect this conversation. |
| Machine Learning          | If you were to use machine learning to analyze this network traffic dump, what features would you focus on? Generate new packets based on these features. |
