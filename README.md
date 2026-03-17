# 🔍 AutoAudit — Security Scanner for Python & VBA Scripts

**AutoAudit** is an open-source security auditing tool developed by me that scans Python scripts, VBA macros, and Office files to detect code vulnerabilities — enabling companies to identify and remediate security risks in their automation assets.

---

## ✨ Features

- **Static Analysis (SAST)** — AST-based parsing for Python, regex-based for VBA
- **26 security rules** covering the most critical vulnerability patterns (CWE-mapped)
- **Dual-language support** — Python (`.py`, `.pyw`) and VBA/Office (`.vba`, `.bas`, `.cls`, `.xlsm`, `.docm`, `.pptm` and more)
- **AI-powered dashboard** — React frontend with Claude AI integration for contextual remediation analysis
- **Risk scoring** — Automatic 0–100 risk score per target
- **JSON output** — Structured findings ready for SIEM/SOAR integration
- **Zero external dependencies** — Core engine runs on Python stdlib only

---

## 🚨 Vulnerability Categories Detected

### Python
| Rule ID | Vulnerability | Severity | CWE |
|---------|--------------|----------|-----|
| PY001 | `eval()` with external input | CRITICAL | CWE-78 |
| PY002 | `exec()` dynamic execution | CRITICAL | CWE-78 |
| PY003 | `compile()` with dynamic strings | HIGH | CWE-78 |
| PY004 | `subprocess` with `shell=True` | CRITICAL | CWE-78 |
| PY005 | `os.system()` with dynamic args | HIGH | CWE-78 |
| PY006 | `os.popen()` command execution | HIGH | CWE-78 |
| PY007 | `pickle.load()` insecure deserialization | HIGH | CWE-502 |
| PY008 | `yaml.load()` without safe Loader | HIGH | CWE-502 |
| PY009 | `marshal.loads()` deserialization | HIGH | CWE-502 |
| PY010 | `requests` with `verify=False` | MEDIUM | CWE-295 |
| PY011 | MD5 usage (deprecated algorithm) | LOW | CWE-327 |
| PY012 | SHA1 usage (weak algorithm) | LOW | CWE-327 |
| PY013 | SQL injection via string concatenation | CRITICAL | CWE-89 |
| PY014 | Hardcoded credentials/secrets | CRITICAL | CWE-798 |
| PY015 | Exposed API keys / tokens | CRITICAL | CWE-798 |

### VBA / Office Macros
| Rule ID | Vulnerability | Severity | CWE |
|---------|--------------|----------|-----|
| VBA001 | Auto-execution macros (`Workbook_Open`, etc.) | HIGH | CWE-284 |
| VBA002 | `Shell()` — external process execution | CRITICAL | CWE-78 |
| VBA003 | `WScript.Shell` — command execution | CRITICAL | CWE-78 |
| VBA004 | `FileSystemObject` — filesystem access | MEDIUM | CWE-552 |
| VBA005 | XMLHTTP — external content download | HIGH | CWE-494 |
| VBA006 | References to system interpreters (cmd, powershell) | HIGH | CWE-78 |
| VBA007 | SQL injection via string concatenation | CRITICAL | CWE-89 |
| VBA008 | Hardcoded credentials in macro | CRITICAL | CWE-798 |
| VBA009 | Credentials in connection strings | CRITICAL | CWE-798 |
| VBA010 | Windows Registry access | MEDIUM | CWE-284 |
| VBA011 | Script execution via wscript/mshta | CRITICAL | CWE-78 |

---

## 🏗️ Project Structure

```
autoaudit/
├── engine/
│   └── scanner.py          # Core scanning engine (Python + VBA)
├── dashboard/
│   └── autoaudit-dashboard.jsx   # React dashboard with Claude AI integration
├── samples/
│   ├── analise_dados.py    # Sample vulnerable Python script (demo)
│   └── macro_legada.vba    # Sample vulnerable VBA macro (demo)
├── docs/
│   ├── ARCHITECTURE.md     # Technical architecture deep-dive
│   ├── RULES.md            # Complete rule reference
│   └── COMMERCIAL.md       # Consulting service model guide
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 18+ (for the dashboard only)

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_ORG/autoaudit.git
cd autoaudit
```

### 2. Run a scan (no installation needed)
```bash
# Scan a directory
python engine/scanner.py /path/to/scripts/

# Scan a single file
python engine/scanner.py /path/to/script.py

# Run on the included samples
python engine/scanner.py samples/
```

### 3. Scan output
```
🔍 AutoAudit Scanner — Setec Consulting Group
   Target: samples/
   Iniciando varredura...

✅ Scan concluído — ID: 3B271E2A
   Arquivos analisados: 2
   Total de findings:   23
   🔴 Critical: 12  🟠 High: 9  🟡 Medium: 2  🔵 Low: 0
   Risk Score: 100.0/100

   📄 JSON salvo em: scan_result_3B271E2A.json
```

### 4. Dashboard (React + Claude AI)
The dashboard file (`dashboard/autoaudit-dashboard.jsx`) is a self-contained React component that:
- Loads scan results directly in the UI
- Provides filtering by severity, language, and keyword search
- Integrates with **Claude AI** (Anthropic API) for per-finding deep analysis
- Generates AI-powered executive reports for C-level/CISO presentation

To use in a React project:
```bash
# Install in your existing React app
cp dashboard/autoaudit-dashboard.jsx src/components/
# Import and render <AutoAuditDashboard />
```

To use as a standalone Claude.ai artifact:
- Open [claude.ai](https://claude.ai)
- Upload the `.jsx` file as an artifact
- The dashboard renders immediately with the embedded demo scan data

---

## 📄 JSON Output Schema

```json
{
  "scan_id": "3B271E2A",
  "target_path": "samples/",
  "started_at": "2026-03-16T18:45:59",
  "finished_at": "2026-03-16T18:45:59",
  "files_scanned": 2,
  "total_findings": 23,
  "critical": 12,
  "high": 9,
  "medium": 2,
  "low": 0,
  "risk_score": 100.0,
  "findings": [
    {
      "file": "samples/analise_dados.py",
      "line": 19,
      "rule_id": "PY001",
      "rule_name": "Uso de eval() com input externo",
      "severity": "CRITICAL",
      "category": "Code Injection",
      "description": "...",
      "evidence": "resultado = eval(user_input)",
      "cwe": "CWE-78",
      "remediation": "...",
      "language": "Python"
    }
  ],
  "file_inventory": [...]
}
```

---

## 🏛️ Architecture

```
Target Path / Repo
      │
      ▼
┌─────────────────┐
│  File Scanner   │  os.walk / pathlib — recursive traversal
│  (Orchestrator) │  Extension filtering: .py .vba .xlsm .docm ...
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌──────────┐
│ Python │ │   VBA    │
│Scanner │ │ Scanner  │
│(AST +  │ │ (Regex   │
│ Regex) │ │  based)  │
└────┬───┘ └────┬─────┘
     │          │
     └────┬─────┘
          ▼
   ┌─────────────┐
   │ Rule Engine │  26 rules → Finding objects
   │  + Scoring  │  Risk Score = Σ(severity_weight) / max_possible × 100
   └──────┬──────┘
          ▼
   ┌─────────────┐
   │ JSON Report │  Structured output → Dashboard / SIEM / PDF
   └─────────────┘
```

---

## 🔧 Extending — Adding Custom Rules

### Python rules (regex)
Add to any list in `PythonScanner` (e.g., `HARDCODED_SECRETS`):
```python
(r'your_regex_pattern',
 'PY999', 'Rule Name', 'HIGH', 'CWE-XXX',
 'Remediation guidance for developers.'),
```

### VBA rules
Add to `VBAScanner.PATTERNS`:
```python
(r'your_vba_pattern',
 'VBA999', 'Rule Name', 'CRITICAL', 'CWE-78', 'Category Name',
 'Remediation guidance.'),
```

### Rule severity weights (risk score)
```python
SEVERITY_WEIGHTS = {
    'CRITICAL': 10,
    'HIGH': 5,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
}
```

---

## 🗺️ Roadmap

### v1.1 — Repository Integration
- [ ] GitHub / GitLab / Azure DevOps OAuth connector
- [ ] Scan full repository branches via API (no local clone required)
- [ ] PR-level diff scanning (scan only changed files)
- [ ] GitHub Actions workflow template

### v1.2 — Endpoint Agent
- [ ] Lightweight Windows/Linux agent (PyInstaller executable)
- [ ] Encrypted findings transmission to central dashboard
- [ ] Network drive (SMB) scanning support
- [ ] Windows Service / Linux daemon mode

### v1.3 — Reporting & Integrations
- [ ] PDF executive report generator
- [ ] Word/DOCX remediation roadmap export
- [ ] Webhook output for SIEM/SOAR integration
- [ ] Splunk / Elastic SIEM connector

### v2.0 — Platform
- [ ] Multi-tenant SaaS backend (FastAPI + PostgreSQL)
- [ ] Continuous monitoring with scheduled scans
- [ ] Trend dashboard (findings over time)
- [ ] Team-based access control

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-rule-py016`
3. Add your rule with tests
4. Submit a Pull Request with rule description, CWE reference, and test case

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🏢 About

My work focuses on building scalable automation environments, structuring Centers of Excellence, and implementing governance models that allow companies to expand RPA, AI, and Agentic AI safely and sustainably.

AutoAudit was created as part of a SecureAutomation approach designed to help organizations assess, secure, and govern their automation landscape, ensuring risk control, compliance, and long-term scalability of digital initiatives. The solution is used to evaluate automation platforms, identify vulnerabilities, define remediation plans, and establish continuous monitoring practices aligned with enterprise architecture and security standards.

Commercial services built on AutoAudit

Security Audit, structured diagnostic engagement typically ranging from R$15k to R$80k depending on scope and environment size.
Remediation Project, implementation of corrections and improvements delivered in fixed-price phases or time and material model.
Continuous Monitoring, recurring managed service focused on governance, security, and operational stability of automation environments.

For commercial inquiries
strafacci.gilberto@gmail.com
