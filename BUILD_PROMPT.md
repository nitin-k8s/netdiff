# Network Device Log Analyzer - Build Prompt

Build a web application that analyzes pre/post change logs from network devices, generates HTML diff reports, and provides a query interface.

## Requirements

1. Parse network device logs (Cisco/Juniper format) from pre/ and post/ directories
2. Generate side-by-side HTML diff reports with expand/collapse
3. Mask dynamic data (timestamps, counters, uptime) before diffing
4. Rule-based query engine for questions like "What interfaces went down?"
5. Support local folder browsing and remote file service (OpenShift)
6. Stateless design - in-memory session storage, no database
7. Downloadable reports (HTML single-file or ZIP)

## Tech Stack

- Python 3.11+, FastAPI, Jinja2, difflib, httpx
- Vanilla HTML/CSS/JS frontend (no framework)

## File Structure

```
log-analyzer/
├── app.py                      # FastAPI app
├── config.yaml
├── requirements.txt
├── core/
│   ├── __init__.py
│   ├── config.py               # Pydantic settings
│   ├── parser.py               # Log parser
│   ├── masker.py               # Data masking
│   ├── differ.py               # Diff generation
│   ├── query_engine.py         # Rule-based queries
│   ├── memory_storage.py       # Session storage
│   ├── report_generator.py     # HTML reports
│   └── file_service.py         # Local/remote files
├── frontend/
│   └── index.html
└── test_changes/
    ├── pre/*.log
    └── post/*.log
```

## Core Logic

### Parser (core/parser.py)
```python
# Extract commands from logs using prompt patterns
PATTERNS = [r'^[\w\-]+[#>]\s*(.+)$', r'^admin@[\w\-]+[>#]\s*(.+)$']

# Glob patterns for pre/post logs (first match wins)
PRE_FILE_GLOBS = ['*pre*.log', '*pre*.txt']
POST_FILE_GLOBS = ['*post*.log', '*post*.txt']

def parse_change_directory(path) -> Dict[str, Tuple[DeviceLog, DeviceLog]]:
    # Return {hostname: (pre_log, post_log)}
    # Hostname from directory name
```

### Masker (core/masker.py)
```python
MASKING_PROFILES = {
    "minimal": ["timestamps"],
    "standard": ["timestamps", "session_ids", "uptime"],
    "strict": ["timestamps", "session_ids", "uptime", "counters"],
}

PATTERNS = {
    'timestamps': [r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', r'\d{2}:\d{2}:\d{2}\.\d+'],
    'uptime': [r'uptime[:\s]+[\d\w\s,]+', r'\d+\s+(days?|hours?|minutes?)'],
    'counters': [r'(\d+)\s+(packets?|bytes?|errors?)'],
    'session_ids': [r'session[_-]?id[:\s]+[\w\-]+'],
}
# Replace matches with <MASKED> or <DURATION>
```

### Differ (core/differ.py)
```python
@dataclass
class CommandDiff:
    command: str
    has_changes: bool
    pre_output: str
    post_output: str
    diff_html: str
    added_lines: int    # RAW count from unified_diff
    removed_lines: int  # RAW count from unified_diff

def generate_command_diff(command, pre, post):
    # 1. Apply masking
    # 2. Split into lines, handle empty inputs: if not lines: lines = ['']
    # 3. Generate HTML with difflib.HtmlDiff(wrapcolumn=80).make_table(..., context=False)
    # 4. Count +/- lines from unified_diff (RAW counts, no adjustment)
```

### Query Engine (core/query_engine.py)
```python
# Pattern matching only
QUERY_TYPES = {
    'interface_down': ['down', 'interface', 'went down'],
    'interface_up': ['up', 'came up'],
    'errors': ['error', 'warning', 'fail'],
    'bgp': ['bgp', 'neighbor'],
    'ospf': ['ospf', 'adjacency'],
    'summary': ['summary', 'overview', 'changes'],
}

def query(question: str) -> QueryResult:
    # 1. Detect query type from keywords
    # 2. Search device_diffs for matching patterns
    # 3. Return structured result with device/command matches
```

### Session Storage (core/memory_storage.py)
```python
@dataclass
class AnalysisSession:
    session_id: str
    change_number: str
    created_at: datetime
    devices: Dict[str, DeviceSummary]
    commands: Dict[str, List[CommandSummary]]  # hostname -> commands
    device_diffs: List[DeviceDiff]  # For query engine
    device_logs: Dict  # For query engine

class SessionManager:
    MAX_SESSIONS = 100
    SESSION_TTL_MINUTES = 30
    _sessions: OrderedDict  # LRU with threading.Lock
    
    def create_session(change_number) -> AnalysisSession
    def get_session(session_id) -> Optional[AnalysisSession]
    def get_session_by_change(change_number) -> Optional[AnalysisSession]
    
# Memory optimization: CommandSummary stores only diff_html, not pre/post output
# Fetch raw output from device_diffs on demand in get_command_diff()
```

### Report Generator (core/report_generator.py)
```python
# Generate self-contained HTML with embedded CSS/JS
# Index page: device cards with status badges, pagination
# Device pages: collapsible command sections with diff tables
# All links relative (../index.html, devices/router1.html)
# JS functions: toggleDiff(), filterCommands(), toggleAll()

# IMPORTANT: Generate diff HTML even when pre_output is empty
if cmd.has_changes:
    diff_html = generate_diff(pre_output or "", post_output or "")
```

### File Service (core/file_service.py)
```python
def get_mode() -> str:  # "local" or "openshift"
    # Auto-detect: check KUBERNETES_SERVICE_HOST or OPENSHIFT_BUILD_NAME

# Local: get_drives(), list_directory(), validate_change_directory()
# Remote: test_connection(), list_remote_directory(), download_change_directory()
```

## API Endpoints

```python
# All data endpoints require session_id or change_number parameter

POST /api/analyze
  Request: {change_directory, masking_profile, include_unchanged}
  Response: {session_id, change_number, total_devices, devices_with_changes,
             report_url, legacy_report_url, statistics}

POST /api/chat
  Request: {question, session_id}
  Response: {answer, change_number, session_id}

GET /api/devices?session_id=X&page=1&page_size=50&status=changed
GET /api/devices/{hostname}/commands?session_id=X
GET /api/devices/{hostname}/diff/{command}?session_id=X
GET /api/statistics?session_id=X

GET /api/download/{change_number}?format=html  # Single file
GET /api/download/{change_number}?format=zip   # All files

GET /api/sessions  # List active sessions
DELETE /api/sessions/{session_id}

# File browsing
GET /api/browse/drives
POST /api/browse/directory  {path}
POST /api/browse/validate   {path}
GET /api/environment
```

## Frontend Key Points

```javascript
let currentSessionId = null;

// After analyze, store session_id
const data = await response.json();
currentSessionId = data.session_id;

// Include session_id in all subsequent requests
fetch('/api/chat', {
    body: JSON.stringify({ question, session_id: currentSessionId })
});

// Folder browser: use data attributes for Windows paths
html += `<div data-path="${encodeURIComponent(item.path)}">`;
el.addEventListener('click', () => {
    const path = decodeURIComponent(el.dataset.path);
});
```

## Config (config.yaml)

```yaml
app:
  port: 8002
  mode: "auto"  # local, openshift, auto

masking:
  enabled: true
  default_profile: "standard"
```

## Requirements.txt

```
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.6.1
pydantic-settings==2.1.0
jinja2==3.1.3
httpx==0.27.0
pyyaml==6.0.1
python-multipart==0.0.6
```

## Test Data Format

User provides path to folder containing device directories:
```
/path/to/logs/           # User browses to this path
├── router1/             # Device hostname = folder name
│   ├── pre.log          # Matches *pre*.log or *pre*.txt
│   └── post.log         # Matches *post*.log or *post*.txt
└── router2/
    └── ...
```

Log file format (command: prefix):
```
# router1/pre.log
command: show interfaces status
Gi0/1     Uplink    connected    1    a-full  a-1000
Gi0/2     Server1   connected   10    a-full  a-1000

command: show logging | include Error|Warning

# router1/post.log  
command: show interfaces status
Gi0/1     Uplink    connected    1    a-full  a-1000
Gi0/2     Server1   notconnect  10    auto    auto

command: show logging | include Error|Warning
Feb 6 10:15:23: %LINK-3-UPDOWN: Interface Gi0/2, changed state to down
```

## Critical Implementation Details

1. **Statistics**: Count devices where `commands_with_changes > 0`, not status field
2. **Diff HTML**: Use `context=False` to show all lines, handle empty pre/post
3. **Line counts**: Show RAW +/- counts from unified_diff, don't subtract
4. **Pydantic**: Use `model_config = ConfigDict(extra="ignore")`
5. **Windows paths**: Use encodeURIComponent in data attributes, not inline onclick
