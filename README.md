# SafeLine IP Range Synchronization

This project provides a modular Python system to automatically synchronize IP ranges from various external sources (e.g., Google, Bing, OpenAI, Meta, AbuseIPDB) with SafeLine IP groups.

It ensures that SafeLine always contains up-to-date IP information from trusted crawlers and blacklists, with automatic batching, grouping, and state tracking.

---

## Table of Contents

- [Requirements](#requirements)
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Environment Configuration](#environment-configuration)
- [Configuration (YAML Sources)](#configuration-yaml-sources) 
- [YAML Key Reference](#yaml-key-reference)
- [How to Add a New Source](#how-to-add-a-new-source)
- [AbuseIPDB Integration](#abuseipdb-integration)
- [SafeLine Integration](#safeline-integration)
- [Deployment](#deployment)
- [Running with Docker](#running-with-docker)
- [License](#license)

---

## Requirements

- \>= Python3.7
- python3 venv
- pip3

---

## Installation

- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip3 install -r requirements.txt`

---

## Overview

The synchronization process fetches IP lists or CIDR ranges from public sources and updates the corresponding SafeLine IP groups.

Each source is compared against its last known update timestamp to avoid unnecessary API calls or updates.  
AbuseIPDB is handled separately due to its large dataset (tens of thousands of IPs).

---

## Features

- Fetches and parses IP/CIDR data from multiple APIs, JSON and RADb feeds.
- Detects updates via timestamps (e.g. `creationTime` or `generatedAt`).
- Automatically updates SafeLine ip groups using the SafeLine API.
- Creates allow/deny rules based on config files per data source (e.g. googlebot)
- Handles AbuseIPDB blacklists via batching and chunked uploads.
- Maintains state in `.ipranges_state.json` for efficient comparisons.

---

## Architecture

```
main.py                          # Entry point for all source processing (json-cidrs, radb, abuseipdb)
requirements.txt                 # Python dependency list
.ipranges_state.json             # Stores last-known timestamps and hash states for change detection

├── api/
│   ├── safeline.py              # Wrapper for SafeLine API (get, update, append, create, delete groups)
│   ├── abuse_ip.py              # Functions for AbuseIPDB blacklist fetching and parsing
│   └── rules.py                 # Management of SafeLine rules (list, get, create, update, sync)
│
├── config/
│   ├── .env                     # Secrets storage (safeline url; token)
│   ├── credentials.py           # Loads environment variables using Pydantic (e.g. SAFELINE_BASE_URL, API_TOKEN)
│   ├── sources.py               # Reads and validates all YAML source definitions from `sources.d/`
│   └── sources.d/               # Contains modular YAML configs per source
│       ├── abuseip.yaml
│       ├── ahrefs.yaml
│       ├── bingbot.yaml
│       ├── duckduckgo.yaml
│       ├── google-special-crawlers.yaml
│       ├── googlebot.yml
│       ├── gptbot.yaml
│       └── meta.yaml
│
├── helpers/
│   ├── parse_source.py          # Central handler for processing each source kind (json-cidrs, radb, abuseipdb)
│   ├── grouping.py              # Core logic for creating/updating grouped IP sets in SafeLine
│   ├── rules_sync.py            # Ensures SafeLine rules match active IP groups (add/remove groups dynamically)
│   ├── rule_init.py             # Safe initialization wrapper for rule creation before first sync
│   ├── chunks.py                # Utilities for splitting IP lists into manageable batch sizes
│   ├── dedup.py                 # Removes duplicate CIDRs/IPs from lists
│   ├── creation_time.py         # Extracts and compares JSON timestamp fields
│   ├── hash.py                  # Hash utilities for detecting data changes (RADB, JSON, etc.)
│   ├── json_helpers.py          # Fetching and parsing of JSON-based IP range sources
│   ├── radb.py                  # Fetches network prefixes from RADB via whois queries
│   ├── rules/                   # (optional grouping for advanced rule handling if added later)
│   ├── group_name.py            # Standardized naming for groups (e.g., parc_bingbot-001)
│   ├── state.py                 # Handles persistent `.ipranges_state.json` I/O
│   ├── rule_init.py             # Safe wrapper for ensure_rule_for_source()
│   ├── rules_sync.py            # Syncs rule membership to match created/deleted groups
│   ├── classes/
│   │   └── rule_extract.py      # Extracts and structures relevant rule fields from SafeLine rule JSONs
│   └── __init__.py              # Makes helpers importable as a package
│
├── patch/
│   └── safeline.py              # Experimental/temporary patch or extension for SafeLine API
│
└── meta.py                      # Utility for Meta (Facebook) GeoFeed CSV / WHOIS parsing and IP extraction
```

---

## Environment Configuration

All runtime credentials and API endpoints are managed via an .env file.
A sample configuration is provided as **.env.example**

Before running the project, renaming or copying of the file is required.
```
cp config/.env.example config/.env
```

---

## Configuration (YAML Sources)

All source integrations are defined as individual YAML configuration files located in  
`config/sources.d/`.  
Each YAML file describes one data source, including its type, origin, and synchronization behavior with SafeLine.

### Example: `bingbot.yaml`

```yaml
enabled: true
kind: json-cidrs
group_base: bingbot
urls:
  - https://www.bing.com/toolbox/bingbot.json
json:
  timestamp_field: creationTime
  cidr_fields:
    - ipv4Prefix
    - ipv6Prefix
rules:
  policy: allow
  enabled: true
upload:
  max_per_group: 10000
  initial_batch_size: 10000
  append_batch_size: 500
  sleep_between_batches: 0.4
  cleanup: delete
  placeholder_ip: 192.0.2.1
```
> Note: all configs are enabled by default and rule policy is set so **allow**

---

### YAML Key Reference

| Key | Type | Description |
|------|------|-------------|
| **enabled** | `bool` | Whether this source is active and should be processed. |
| **kind** | `string` | Defines the source type:<br>• `json-cidrs` – for JSON IP ranges (e.g., Google, Bing, OpenAI)<br>• `whois-radb` – for ASN-based whois lookups (e.g., Meta/Facebook)<br>• `abuseipdb` – for AbuseIPDB blacklist fetching. |
| **group_base** | `string` | Base name used for group creation (`parc_<group_base>-001`). |
| **json** | `dict` *(optional)* | JSON-specific options:<br>• `timestamp_field` → key for creation time<br>• `cidr_fields` → fields containing CIDRs (usually `ipv4Prefix` and `ipv6Prefix`). |
| **urls** | `list` | List of API or JSON URLs to fetch from (used for `json-cidrs`). |
| **radb** | `dict` *(optional)* | RADB-specific configuration:<br>• `asn` → the ASN to query (e.g. `AS32934` for Meta). |
| **api** | `dict` *(optional)* | AbuseIPDB-specific configuration:<br>• `url` → API endpoint<br>• `confidence_min` → minimum confidence threshold<br>• `timestamp_path` → path to “generatedAt” field<br>• `api_key` → (optional) if not loaded from `.env`. |
| **upload** | `dict` | Upload behavior and limits:<br>• `max_per_group` → SafeLine’s 10k limit<br>• `initial_batch_size` / `append_batch_size` → chunk sizes for updates<br>• `sleep_between_batches` → delay between upload batches<br>• `cleanup` → how to handle extra groups (`delete`, `placeholder`, `clear`, `keep`)<br>• `placeholder_ip` → fallback IP if placeholders are used. |
| **rules** | `dict` | Rule synchronization configuration:<br>• `policy` → `allow` or `deny`<br>• `enabled` → whether the rule should be active<br>• `name` *(optional)* → custom rule name override. |

---

### Notes

- The `group_base` is automatically prefixed with **`parc_`** when creating SafeLine groups.  
  Example: `group_base: bingbot` → groups `parc_bingbot-001`, `parc_bingbot-002`, etc. 
> To change group prefix: helpers/parse_sources.py:22
- Each YAML file is **fully independent** — disabling one source (e.g. `enabled: false`) will not affect others.
- The YAMLs are dynamically loaded via `config/sources.py`, so new sources can be added without modifying any Python code.
- If a source is missing its SafeLine rule, it will be **automatically created** based on the policy defined in the YAML.

---

## How to Add a New Source

1. **Create a new YAML file** in `config/sources.d/`  
   Example: `openai.yaml`

2. **Define the configuration**
   ```yaml
   enabled: true
   kind: json-cidrs
   group_base: gptbot
   urls:
     - https://openai.com/gptbot.json
   upload:
     max_per_group: 10000
     initial_batch_size: 500
     append_batch_size: 500
     sleep_between_batches: 0.4
     cleanup: delete
     placeholder_ip: 192.0.2.1
   rules:
     policy: deny
     enabled: true
   ```

3. **Run the sync**
   ```bash
   python3 main.py --only gptbot
   ```

4. The system will automatically:
   - Load and validate your YAML file
   - Create SafeLine groups as needed
   - Apply batching and rate limits automatically
   - Create or update the associated SafeLine rule

---

## AbuseIPDB Integration

The AbuseIPDB blacklist can contain up to 500,000 IPs. The maximum amount to retrieve is based on the selected plan.
- Free: 10,000
- Basic: 100,000
- Premium: 500,000

> [abuseip plan overview](https://www.abuseipdb.com/pricing)

Since SafeLine only allows **10,000 entries per group**, the system automatically:

1. Splits IPs into 10k chunks.
2. Assigns each chunk to a dedicated SafeLine group (`parc_abuseip-001`, `parc_abuseip-002`, etc.).
3. Uses **Replace + Append** logic for stable uploads:
   - First batch uses `update` (Replace)
   - Remaining batches use `append` (Add)

This design ensures efficient synchronization and reduces risk of timeouts for the cost of performance.

---

## SafeLine Integration

The SafeLine API is used to:
- Fetch existing group IDs.
- Create or update IP groups.
- Append IPs in small batches to reduce load.

All requests include necessary authentication headers and support both `verify=False` (for internal networks) and configurable base URLs via environment variables.

---

## Deployment

### Environment Variables

| Variable             | Description           |
|----------------------|-----------------------|
| `SAFELINE_BASE_URL`  | SafeLine API base URL |
| `SAFELINE_API_TOKEN` | SafeLine API token    |
| `ABUSEIPDB_KEY`      | AbuseIPDB API key     |

### Running the Synchronization

```bash
python main.py
```

This will:
- Fetch all configured IP/CIDR sources.
- Compare with the saved state.
- Update SafeLine groups where needed.

### Recommended scheduled execution

- `*/5 * * * * python3 main.py --kind json-cidrs` - fast fetched, rarely changes
- `3 */1 * * * python3 main.py --kind whois-radb` - fetched hourly
- `0 */1 * * * python3 main.py --kind abuseipdb`  - frequently updated

---

## Running with Docker

### 1. Clone the repository
```bash
git clone https://github.com/parcnetwork/safeline-ipgroup-sources-sync.git
cd safeline-ipgroup-sources-sync
```

### 2. Configure environment variables
Copy the example configuration and edit it with your credentials:

```bash
cp config/.env.example config/.env
```

Edit `config/.env`:

```dotenv
SAFELINE_BASE_URL=https://<your-safeline-host>:9443/api
SAFELINE_API_TOKEN=xxxxxxx
ABUSEIPDB_KEY=xxxxxxx     # optional, if AbuseIPDB source is enabled
LOG_LEVEL=INFO
```

### 3. Run the container

```bash
docker pull docker.io/parcnetwork/safeline-ipgroup-sources-sync:latest

mkdir -p persist

docker run --rm -it \
  --name ip-sync \
  --env-file ./config/.env \
  -v "$(pwd)/config:/app/config:ro" \
  -v "$(pwd)/persist:/app/persist" \
  docker.io/parcnetwork/safeline-ipgroup-sources-sync:latest \
  --only bingbot
```

### 5. Additional options

| Option | Description |
|---------|-------------|
| `--only <source>` | Run only one specific source (e.g. `--only abuseipdb`) |
| `--kind <type>` | Filter by source type (`json-cidrs`, `whois-radb`, `abuseipdb`) |
| `LOG_LEVEL=DEBUG` | Enable detailed debug output |
| Persistent volume | The file `.ipranges_state.json` is stored inside `/app/persist` |


## License

This project is proprietary to **parc-network**.  
All rights reserved. Redistribution or modification is not permitted without authorization.
