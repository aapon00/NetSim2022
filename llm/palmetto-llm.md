# Running LLMs on Palmetto

## Metadata

* Author: Nathan Goller-Deitsch (ngd@clemson.edu)
* Last updated: December 15, 2023

## Introduction

This document describes how to run large language models like LLaMa and Zephyr on Palmetto, Clemson's high performance computing cluster. It is aimed at users who are new to Palmetto and/or HPC in general.

## Prerequisites

* **Palmetto Account**: Ensure you have an active account on Palmetto. If you don't have one, request access [here](https://docs.rcd.clemson.edu/palmetto/accounts/new_account/).

## Accessing the Cluster

Connect to Palmetto using SSH:

```bash
ssh <username>@login.palmetto.clemson.edu
```

## Selecting the Appropriate Hardware

Run the following command to see current availability of Palmetto's compute nodes:

```bash
whatsfree
```

Identify a combination of CPU and GPU that has appropriate specifications for your task and at least one available node (i.e FREE = 1 or more). Note this combination for later use.

## Setting up `llama.cpp`

### Request an Interactive Node
Request an interactive node that matches your chosen hardware specification. Note that the chip type should be specified in all lowercase. For example:

```bash
qsub -I -l select=1:ncpus=1:mem=30gb:chip_type=e5-2680v4:ngpus=1:gpu_model=p100
```

### Load Modules

Once on the interactive node, search for available CUDA modules and load the one that is compatible with your GPU. For example:

```bash
module avail # Find available modules
module load cuda/12.1.1-gcc/9.5.0 # Choose a CUDA version that is compatible with your GPU
```

### Download `llama.cpp`
Clone the `llama.cpp` repository into your scratch directory (or another appropriate location):

```bash
cd /scratch/<username>
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp
```

### Update `Makefile`
The `Makefile` is looking for CUDA in the wrong location. First, run `echo $CUDA_HOME` to see where CUDA is installed. You should get a result like:

```bash
/software/spackages/linux-rocky8-x86_64/gcc-9.5.0/cuda-12.1.1-d4ik3tbvtk3ypske36p4ogeulsnsv26p
```

In your favorite text editor, open the `Makefile` in the root of the `llama.cpp` repository. Find the section beginning `ifdef LLAMA_CUBLAS`. Add a line defining `CUDA_PATH` to point to the folder you just found, and update the `MK_CPPFLAGS` line to point to the correct include directory. For example:

```bash
... (other lines) ...

CUDA_PATH := /software/spackages/linux-rocky8-x86_64/gcc-9.5.0/cuda-12.1.1-d4ik3tbvtk3ypske36p4ogeulsnsv26p

ifdef LLAMA_CUBLAS
        MK_CPPFLAGS  += -DGGML_USE_CUBLAS -I$(CUDA_PATH)/include

... (other lines) ...
```

### Build `llama.cpp`

Run the following command to build `llama.cpp`:

```bash
make clean && LLAMA_CUBLAS=1 make -j
```

### Download a model

Find a model in .gguf format and download it to your scratch directory. For example:

```bash
cd /scratch/<username>
wget https://huggingface.co/TheBloke/zephyr-7B-beta-GGUF/blob/main/zephyr-7b-beta.Q5_K_M.gguf
```

### Test run `llama.cpp`

Run the following command to test `llama.cpp`:

```bash
/scratch/<username>/llama.cpp/main -m /scratch/<username>/<model>.gguf --gpu-layers 9999 -i
```

If everything is working correctly, you should see an interactive session with your model. You can type to it and receive responses in a ChatGPT-like format. You can exit by pressing `Ctrl+C`.

If tokens are not generating or are generating very slowly (multiple seconds per token), `llama.cpp` is not using your GPU. Check that you have set up CUDA correctly, built `llama.cpp` with the `LLAMA_CUBLAS` flag, and are running `llama.cpp` with the `--gpu-layers` flag (which offloads the first N layers of the model to the GPU).

## Import Prompts

Upload a list of prompts to your scratch directory. For example, we will use the following prompts in `prompts.txt`:

```
Tell me a fun fact about elephants.
Tell me a fun fact about lions.
Tell me a fun fact about tigers.
Tell me a fun fact about giraffes.
Tell me a fun fact about pandas.
```

## Write Batch Job Script

Use your favorite text editor to create a file called `batch_job.sh` in your scratch directory. This file will contain the commands to be run on the cluster. The following is an example of a batch job script that runs `llama.cpp` on a list of prompts:

```bash
#!/bin/bash
#PBS -N zephyr_animals_demo
#PBS -l select=1:ncpus=1:chip_type=e5-2680v4:mem=30gb:ngpus=1:gpu_model=p100
#PBS -l walltime=0:05:00
#PBS -j oe
#PBS -o /scratch/<username>/output/zephyr_animals_demo.log
#PBS -J 1-5

print_timestamp() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1"
}

OUTFILE="/scratch/<username>/output/output_${PBS_ARRAY_INDEX}.txt"

print_timestamp "Starting job on node: $(hostname)"
print_timestamp "PBS Job ID: $PBS_JOBID"
print_timestamp "Output file: $OUTFILE"

# Load required modules
module load cuda/12.1.1-gcc/9.5.0

# Go to the directory where your files and script are located
cd /scratch/<username>/llama.cpp

# Extract the prompt corresponding to the PBS_ARRAY_INDEX, remove quotes
prompt=$(sed -n "${PBS_ARRAY_INDEX}p" prompts.txt | tr -d '"')

print_timestamp "Processing prompt: $prompt"

# Write the prompt to input.txt
echo "$prompt" > input.txt

print_timestamp "Running main command"

# Run your command and save its output
./main -m '/scratch/<username>/zephyr-7b-beta.Q5_K_M.gguf' --gpu-layers 9999 -n 8192 --file input.txt > "$OUTFILE"

print_timestamp "Main command finished"

print_timestamp "Job completed"
```

## Run Batch Job

From the login node, run `qsub batch_job.sh` to submit the batch job. You should see a job ID returned that looks like `1740332[].pbs02`. You can check the status of your job with `qstat -u <username>`.

## Export Results

Once the job is complete, you should see a file called `output_<index>.txt` for each prompt in your output directory.

For example, my `output_1.txt` contained the following (your results will vary depending on model, prompt, and random seed):

```
Tell me a fun fact about elephants.

The largest elephant ever recorded was a male named Jumbo, who lived in the 19th century in Europe and Africa. Jumbo weighed around 23,000 pounds (over 11 tons) and stood over 13 feet tall at the shoulders!
```

## Troubleshooting

You can check the current configuration for each job queue with `checkqueuecfg`. If you submit an array with more elements than the `max_jobs_per_queue`, it will not start. I am not sure how to avoid this issue, but you can work around it by either running multiple prompts in each job array task or by submitting multiple job arrays.

## References

<https://kubito.dev/posts/llama-cpp-linux-nvidia/>

<https://github.com/clemsonciti/palmetto-examples/tree/master/Job-arrays>