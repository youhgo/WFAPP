<p align="center">
  <img src="./ressources/images/app.logo.jpeg" width="600" height="600" alt="APP System Architecture">
</p>



# WFAPP - Windows Forensic Artifacts Parser Pipeline

![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11-blue?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Supported-blue?logo=docker&logoColor=white)
![Wazuh Ready](https://img.shields.io/badge/SIEM-Wazuh%20Ready-orange)
![License](https://img.shields.io/badge/License-Apache%202.0-blue)

WFAPP is a robust, modular, and extremely performant forensic pipeline designed to extract, parse, and normalize a wide range of Windows artifacts. It acts as an orchestrator that leverages community-driven open-source tools to extract raw data, before standardizing it into simplified, human-readable formats (CSV, JSONL).

> **Disclaimer:** I am not a professional developer, and this tool is not secure by design. Therefore, it is ABSOLUTELY NOT recommended to expose the API or Web UI to the internet.

---

## Features

- **Automated Pipeline**: Orchestrates forensic processing workflows with minimal configuration.
- **Wazuh/SIEM Ready**: Automatically standardizes parsed output for easy ingestion by Wazuh or other SIEM solutions.
- **Plug & Play Architecture**: Easily extendable. The community can drop a new parser and a new pipeline in the specific directories and the main Dispatcher will automatically load them.
- **Extremely Low Memory Footprint**: Uses a stream-based (`yield`) reading approach. WFAPP can parse files of several Gigabytes (like huge Amcache hives) without loading the entire file into RAM.

## Supported Artifacts

WFAPP parses the following forensic artifacts out-of-the-box:
- **Event Logs (.evtx)**
- **Windows Registry Hives (SAM, SYSTEM, SOFTWARE, NTUSER, etc.) & Amcache**
- **Web History (Chrome, Edge)**
- **Prefetch (.pf)**
- **System Info (WMI/DFIR-ORC outputs)**
- **Process Activity (Autoruns, Sysmon, AppCompatCache, etc.)**
- **Disk Activity (USN Journal, MFT)**
- **LNK Files (.lnk)**

---

## Installation & Usage

### 1. Requirements
Ensure you have the following dependencies installed:
- Python 3.9+
- Docker & Docker Compose (If using the Web UI / Wazuh stack)

### 2. Environment Configuration
Clone the repository and copy the example environment file:
```bash
git clone <repository_url>
cd WFAPP
cp .env.example .env
```
Edit the `.env` file to configure your paths and desired settings.

### 3. Usage (CLI)

WFAPP can be executed directly from the command line using the `APPEngine`.

```bash
cd APPEngine
python3 main.py -c /path/to/your/config.json -i /path/to/evidences -o /path/to/results
```

**Arguments:**
- `-c` : Path to your execution configuration (defining what to parse).
- `-i` : Input directory containing the raw forensic artifacts (e.g. collected via DFIR-ORC or Kape).
- `-o` : Output directory where the standardized CSV/JSONL results will be saved.

### 4. Running with the Web UI
To spin up the entire ecosystem (WFAPP API + Web interface + Wazuh dashboard), use the provided docker-compose stack:

```bash
docker-compose up -d
```
You can then access the Web UI at the port specified in your `.env`.

---

## Architecture & How It Works

1. **The Dispatcher (`dispatcher.py`)**: This is the heart of the engine. When the engine starts, the Dispatcher automatically scans the `modules/` folder for any class decorated with `@register_pipeline`. It automatically maps them to the appropriate configuration keys.
2. **The Pipelines (`modules/`)**: Pipelines act as the bridge between the raw files and the parsers. They decide *which* files should be parsed (using Regex).
3. **The Parsers (`parsers/`)**: Parsers implement a streaming `parse()` method using Python `yield`. They read a file line by line (or chunk by chunk), normalize the data into a standard Python dictionary, and instantly pass it back to the pipeline.
4. **The Sinks (`classes/BaseParser.py`)**: The Pipeline redirects the yielded dictionary to an Output Sink (`CsvOutputSink`, `JsonlOutputSink`, or `TextOutputSink`). The Sink appends the line to the disk on the fly, drastically reducing memory usage.

## Contributing
Want to add a new artifact? We've designed WFAPP to be 100% Plug & Play. Please check the `DEVELOPER_GUIDE.md` for a comprehensive step-by-step tutorial on how to create your own pipeline in less than 5 minutes!
