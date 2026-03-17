# AutoAudit — Technical Architecture

## Overview

AutoAudit is a two-layer Static Application Security Testing (SAST) tool purpose-built for corporate automation scripts. Unlike general-purpose SAST tools (Bandit, Semgrep), AutoAudit focuses specifically on the threat surface created by Python automation scripts and VBA/Office macros — the most common sources of unmanaged security risk in enterprise environments.

---

## Core Engine (`engine/scanner.py`)

### Design Principles

**Zero external dependencies** — The core engine uses only Python stdlib (`ast`, `re`, `os`, `pathlib`, `json`, `hashlib`). This is intentional: it allows deployment in air-gapped environments and eliminates supply-chain risk from third-party packages.

**Dual analysis strategy** — Python files use AST-based analysis for semantic accuracy (avoiding false positives from commented-out code or strings that look like function calls). VBA files use regex-based analysis since no mature Python AST parser exists for VBA.

**Finding deduplication** — A `seen` set tracks `(filepath, line, rule_id)` tuples to prevent the same rule from firing multiple times on the same line across overlapping patterns.

**Secret masking** — Evidence strings automatically mask sensitive values (keeping only the first 4 chars visible) before storing in findings, preventing the scan report itself from leaking credentials.

---

## Python Scanner — AST Analysis

The `PythonScanner` class uses Python's built-in `ast` module to parse source code into an Abstract Syntax Tree before applying rules. This provides several advantages over pure regex:

```
Source Code
     │
     ▼  ast.parse()
Abstract Syntax Tree (AST)
     │
     ▼  ast.walk()
Every node in the tree
     │
     ▼  isinstance(node, ast.Call)
Function call nodes
     │
     ▼  _get_func_name()
Function name → DANGEROUS_CALLS lookup
     │
     ▼  Finding object
```

**Why AST matters:**
- `# eval(user_input)` — commented out → AST ignores it, regex would flag it
- `eval_count = 10` — variable name containing "eval" → AST ignores it
- `result = eval(safe_literal)` — still flagged, but with correct line number

### Analysis Layers

1. **AST Analysis** — `eval`, `exec`, `compile` with any argument (always risky)
2. **Regex on source lines** — subprocess, deserialization, crypto, SQL, secrets

The two layers are complementary: AST catches semantic patterns, regex catches string patterns that AST doesn't model well (like connection strings or API key formats).

---

## VBA Scanner — Regex Analysis

The `VBAScanner` class applies 11 patterns sequentially against each source line. VBA's limited syntax and the prevalence of specific dangerous APIs (WScript.Shell, MSXML2.XMLHTTP) make regex a practical and accurate approach.

**Extensions handled:**
- `.vba`, `.bas`, `.cls`, `.frm` — extracted VBA module files
- `.vbs` — standalone VBScript files
- `.xlsm`, `.xlsb`, `.xltm` — Excel macro-enabled workbooks
- `.docm` — Word macro-enabled documents
- `.pptm` — PowerPoint macro-enabled presentations

> **Production note:** For true binary Office files (.xlsm, .docm), the production path uses `oletools` (`olevba`) to extract VBA source before applying these patterns. The MVP reads files as text, which works for `.vba`/`.bas` source exports.

---

## Risk Score Calculation

```
risk_score = min( Σ(severity_weight[f]) / max_possible × 100, 100 )

Where:
  severity_weight = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1, INFO: 0 }
  max_possible    = files_scanned × 50  (heuristic: avg 5 findings per file at HIGH)
```

This produces a normalized 0–100 score where:
- **0–25** → Low risk posture
- **26–50** → Moderate risk, targeted remediation recommended
- **51–75** → High risk, structured remediation project needed
- **76–100** → Critical risk, immediate action required

---

## Dashboard Architecture (`dashboard/autoaudit-dashboard.jsx`)

The React dashboard is a self-contained single-file component with no build step required. It embeds the scan results as a JavaScript constant and uses the Anthropic API for AI features.

### Component Tree

```
AutoAuditDashboard
├── ScanningAnimation       # Simulated scan progress (UX)
├── RiskGauge               # SVG circular gauge for risk score
├── Hero Metrics Bar        # Critical / High / Medium / Low counts
├── Tab Navigation
│   ├── FindingsTab
│   │   ├── FilterBar       # Severity, language, keyword filters
│   │   └── FindingCard[]   # One per finding, with AI trigger
│   ├── FilesTab            # Per-file breakdown with severity distribution
│   ├── CategoriesTab       # Category grid with visual proportion bars
│   └── ExecutiveTab        # AI-generated C-level report
└── AIPanel (Modal)         # Per-finding Claude AI analysis + chat
```

### Claude AI Integration

Two AI surfaces are available:

**Per-finding analysis** (`AIPanel`) — Triggered by "Analisar" button on each finding. Sends a structured prompt including the finding metadata and requests: business impact, attack scenario, step-by-step remediation with corrected code, effort estimate, and prioritization guidance.

**Executive report** (`ExecutiveTab`) — Triggered by clicking the "Relatório Executivo" tab. Sends aggregated scan statistics and top findings, requesting a board-ready report structured with: executive diagnosis, risk surface, top 3 risks with business impact, phased remediation plan (30/60/ongoing days), effort/cost estimate, and next step.

Both surfaces support follow-up questions via a chat input that maintains conversation context within the modal session.

---

## Data Flow

```
Python Scanner          VBA Scanner
      │                      │
      └──────────┬───────────┘
                 ▼
         AutoAuditScanner.scan()
                 │
                 ▼
         ScanResult dataclass
         {
           scan_id, target_path,
           files_scanned, total_findings,
           critical, high, medium, low,
           risk_score,
           findings: [Finding],
           file_inventory: [FileInfo]
         }
                 │
         ┌───────┴────────┐
         ▼                ▼
    JSON file         React Dashboard
  (integration)      (visualization +
                       AI analysis)
```

---

## Production Deployment Path

### Phase 1: Repository Scanner (Remote)

```
Client grants OAuth token (GitHub/GitLab/Azure DevOps)
         │
         ▼
API clone / tree listing (PyGithub / python-gitlab)
         │
         ▼
Per-file streaming analysis (no full clone needed for text files)
         │
         ▼
Central findings database (PostgreSQL)
         │
         ▼
Multi-client dashboard (FastAPI + React)
```

### Phase 2: Endpoint Agent

```
PyInstaller executable (Windows) / systemd service (Linux)
         │
         ▼
Recursive filesystem scan (local + SMB mounts)
         │
         ▼
Findings encrypted with client key (AES-256-GCM)
         │
         ▼
HTTPS POST to AutoAudit central API
         │
         ▼
Aggregated multi-client dashboard
```

---

## Security Considerations for the Tool Itself

AutoAudit handles potentially malicious code. Key mitigations:

- **No code execution** — The engine never runs the scanned code. AST parsing is safe (Python's `ast.parse` does not execute).
- **Evidence masking** — Credential values are partially masked before storage.
- **No external network calls** — The core engine is fully offline. AI features are opt-in via the dashboard.
- **Read-only filesystem access** — The scanner only reads files; it never writes to the scanned directory.
- **Path traversal protection** — `pathlib.Path` handles path normalization; no `os.path.join` with user input.

---

## References

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [Bandit — Python SAST](https://github.com/PyCQA/bandit) (inspiration for rule structure)
- [oletools — VBA/Office Analysis](https://github.com/decalage2/oletools)
- [Semgrep — Multi-language SAST](https://semgrep.dev) (rule engine reference)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
