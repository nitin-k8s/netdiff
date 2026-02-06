# Network Device Log Analyzer

Analyzes pre/post change logs from network devices, generates HTML diff reports, and provides a query interface.

## Features

- **Log Parsing**: Cisco/Juniper format command/output logs
- **HTML Diff Reports**: Side-by-side diffs with expand/collapse
- **Data Masking**: Mask timestamps, counters, uptime before diffing
- **Query Engine**: Rule-based queries - "What interfaces went down?"
- **Stateless**: In-memory session storage, no database
- **Downloadable**: Single HTML or ZIP archive

## Quick Start

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:8002/ui
```

## Input Format

```
test_changes/
├── router1/
│   ├── pre.log
│   └── post.log
└── router2/
    ├── pre.log
    └── post.log
```

Log files contain device prompts and command outputs:
```
router1#show interfaces status
Gi0/1     Uplink    connected    1    a-full  a-1000
```

## Architecture

```
log-analyzer/
├── app.py                  # FastAPI app
├── config.yaml
├── core/
│   ├── parser.py           # Log parser
│   ├── masker.py           # Data masking
│   ├── differ.py           # Diff generation
│   ├── query_engine.py     # Rule-based queries
│   ├── memory_storage.py   # Session storage (100 sessions, 30 min TTL)
│   ├── report_generator.py # HTML report generation
│   └── file_service.py     # Local/remote file access
└── frontend/
    └── index.html
```

## API

```
POST /api/analyze          # Analyze change directory
POST /api/chat             # Query with session_id
GET  /api/devices          # List devices (paginated)
GET  /api/download/{id}    # Download report (html/zip)
GET  /api/sessions         # List active sessions
```

## Configuration

```yaml
app:
  port: 8002
  mode: "auto"  # local, openshift, auto

masking:
  enabled: true
  default_profile: "standard"  # minimal, standard, strict
```
