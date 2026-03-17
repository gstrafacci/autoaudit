"""
AutoAudit Scanner Engine v1.0
Setec Consulting Group — Security Audit Tool
Detecta vulnerabilidades em scripts Python e VBA/Office
"""

import ast
import re
import os
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime


# ─────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    rule_name: str
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    description: str
    evidence: str
    cwe: str
    remediation: str
    language: str

@dataclass
class ScanResult:
    scan_id: str
    target_path: str
    started_at: str
    finished_at: str
    files_scanned: int
    files_skipped: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    risk_score: float
    findings: List[Finding] = field(default_factory=list)
    file_inventory: List[dict] = field(default_factory=list)


# ─────────────────────────────────────────────
# PYTHON SCANNER (AST-based)
# ─────────────────────────────────────────────

class PythonScanner:
    """Analisa código Python via AST para detectar padrões inseguros."""

    DANGEROUS_CALLS = {
        'eval':    ('PY001', 'Uso de eval() com input externo', 'CRITICAL', 'CWE-78',
                    'Substituir eval() por ast.literal_eval() ou lógica explícita. Nunca avaliar input de usuário.'),
        'exec':    ('PY002', 'Uso de exec() dinâmico', 'CRITICAL', 'CWE-78',
                    'Eliminar exec() dinâmico. Refatorar para funções explícitas e controladas.'),
        'compile': ('PY003', 'Compilação dinâmica de código', 'HIGH', 'CWE-78',
                    'Evitar compile() com strings dinâmicas. Usar módulos com lógica pré-definida.'),
    }

    SUBPROCESS_PATTERNS = [
        (r'subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True', 
         'PY004', 'subprocess com shell=True', 'CRITICAL', 'CWE-78',
         'Remover shell=True. Passar argumentos como lista. Sanitizar todos os inputs.'),
        (r'os\.system\s*\(', 
         'PY005', 'os.system() com argumento dinâmico', 'HIGH', 'CWE-78',
         'Substituir os.system() por subprocess com lista de argumentos e sem shell=True.'),
        (r'os\.popen\s*\(', 
         'PY006', 'os.popen() — execução de comando', 'HIGH', 'CWE-78',
         'Substituir por subprocess.run() com argumentos explícitos.'),
    ]

    DESERIALIZATION_PATTERNS = [
        (r'pickle\.(load|loads)\s*\(',
         'PY007', 'Desserialização insegura com pickle', 'HIGH', 'CWE-502',
         'Nunca usar pickle com dados de fontes externas. Usar JSON ou protobuf validado.'),
        (r'yaml\.load\s*\([^,)]+\)',
         'PY008', 'yaml.load() sem Loader seguro', 'HIGH', 'CWE-502',
         'Substituir por yaml.safe_load() em todos os casos.'),
        (r'marshal\.loads?\s*\(',
         'PY009', 'Desserialização com marshal', 'HIGH', 'CWE-502',
         'Evitar marshal com dados externos. Usar JSON com validação de schema.'),
    ]

    CRYPTO_PATTERNS = [
        (r'requests\.(get|post|put|delete|patch)\s*\([^)]*verify\s*=\s*False',
         'PY010', 'Verificação SSL desabilitada', 'MEDIUM', 'CWE-295',
         'Remover verify=False. Configurar bundle de certificados correto.'),
        (r'hashlib\.md5\s*\(',
         'PY011', 'Uso de MD5 (algoritmo obsoleto)', 'LOW', 'CWE-327',
         'Substituir MD5 por SHA-256 ou SHA-3 para propósitos de segurança.'),
        (r'hashlib\.sha1\s*\(',
         'PY012', 'Uso de SHA1 (algoritmo fraco)', 'LOW', 'CWE-327',
         'Substituir SHA1 por SHA-256 ou SHA-3.'),
    ]

    SQL_PATTERNS = [
        (r'(execute|executemany)\s*\(\s*["\'].*\+|f["\'].*SELECT.*\{',
         'PY013', 'SQL injection — concatenação de string', 'CRITICAL', 'CWE-89',
         'Usar parametrização de queries: cursor.execute(sql, params). Nunca concatenar input do usuário.'),
    ]

    HARDCODED_SECRETS = [
        (r'(?i)(password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?key)\s*=\s*["\'][^"\']{4,}["\']',
         'PY014', 'Credencial/segredo hardcoded', 'CRITICAL', 'CWE-798',
         'Mover credenciais para variáveis de ambiente ou cofre de segredos (Vault, Azure Key Vault, AWS Secrets Manager).'),
        (r'(?i)(bearer|sk-|pk-|ghp_|glpat-|AIza)[A-Za-z0-9_\-]{10,}',
         'PY015', 'Token/API Key exposto no código', 'CRITICAL', 'CWE-798',
         'Revogar token imediatamente. Usar variáveis de ambiente ou secrets manager.'),
    ]

    def scan_file(self, filepath: str) -> List[Finding]:
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                source = f.read()
                lines = source.splitlines()
        except Exception:
            return findings

        # AST Analysis
        findings += self._ast_analysis(filepath, source, lines)
        # Regex patterns
        findings += self._regex_scan(filepath, source, lines)
        return findings

    def _ast_analysis(self, filepath, source, lines) -> List[Finding]:
        findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name in self.DANGEROUS_CALLS:
                    rule_id, rule_name, severity, cwe, remediation = self.DANGEROUS_CALLS[func_name]
                    line_num = node.lineno
                    evidence = lines[line_num - 1].strip() if line_num <= len(lines) else ''
                    findings.append(Finding(
                        file=filepath, line=line_num,
                        rule_id=rule_id, rule_name=rule_name,
                        severity=severity, category='Code Injection',
                        description=f'Função perigosa {func_name}() detectada — pode executar código arbitrário.',
                        evidence=self._mask_secrets(evidence),
                        cwe=cwe, remediation=remediation, language='Python'
                    ))
        return findings

    def _regex_scan(self, filepath, source, lines) -> List[Finding]:
        findings = []
        all_patterns = (
            [(p, rid, rn, sev, cwe, rem, 'Command Injection') for p, rid, rn, sev, cwe, rem in self.SUBPROCESS_PATTERNS] +
            [(p, rid, rn, sev, cwe, rem, 'Insecure Deserialization') for p, rid, rn, sev, cwe, rem in self.DESERIALIZATION_PATTERNS] +
            [(p, rid, rn, sev, cwe, rem, 'Cryptography') for p, rid, rn, sev, cwe, rem in self.CRYPTO_PATTERNS] +
            [(p, rid, rn, sev, cwe, rem, 'SQL Injection') for p, rid, rn, sev, cwe, rem in self.SQL_PATTERNS] +
            [(p, rid, rn, sev, cwe, rem, 'Hardcoded Secrets') for p, rid, rn, sev, cwe, rem in self.HARDCODED_SECRETS]
        )

        seen = set()
        for pattern, rule_id, rule_name, severity, cwe, remediation, category in all_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    key = (filepath, i, rule_id)
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            file=filepath, line=i,
                            rule_id=rule_id, rule_name=rule_name,
                            severity=severity, category=category,
                            description=self._get_description(category, rule_name),
                            evidence=self._mask_secrets(line.strip()),
                            cwe=cwe, remediation=remediation, language='Python'
                        ))
        return findings

    def _get_func_name(self, node) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ''

    def _get_description(self, category, rule_name) -> str:
        descriptions = {
            'Command Injection': 'Execução de comandos do sistema com entrada potencialmente não sanitizada.',
            'Insecure Deserialization': 'Desserialização de dados de fonte não confiável pode executar código arbitrário.',
            'Cryptography': 'Configuração criptográfica insegura detectada.',
            'SQL Injection': 'Construção insegura de query SQL — risco de SQL Injection.',
            'Hardcoded Secrets': 'Credencial ou segredo encontrado diretamente no código-fonte.',
        }
        return descriptions.get(category, rule_name)

    def _mask_secrets(self, text: str) -> str:
        """Ofusca parcialmente valores sensíveis na evidência."""
        return re.sub(
            r'(["\'])([A-Za-z0-9_\-@!#$%^&*]{4})[A-Za-z0-9_\-@!#$%^&*]+(["\'])',
            r'\1\2****\3', text
        )


# ─────────────────────────────────────────────
# VBA SCANNER (Regex-based)
# ─────────────────────────────────────────────

class VBAScanner:
    """Analisa arquivos VBA/macro Office para detectar padrões maliciosos."""

    PATTERNS = [
        # Auto-execução
        (r'(?i)(Sub\s+)(Workbook_Open|Document_Open|Auto_Open|AutoOpen|AutoExec)',
         'VBA001', 'Macro de auto-execução', 'HIGH', 'CWE-284', 'Execução Automática',
         'Remover ou auditar macros com auto-execução. Implementar assinatura digital de macros.'),

        # Shell e execução de processos
        (r'(?i)\bShell\s*\(',
         'VBA002', 'Shell() — execução de processo externo', 'CRITICAL', 'CWE-78', 'Command Injection',
         'Remover chamadas Shell(). Substituir por automação controlada via API segura.'),

        (r'(?i)CreateObject\s*\(\s*["\']WScript\.Shell["\']',
         'VBA003', 'WScript.Shell — execução de comandos', 'CRITICAL', 'CWE-78', 'Command Injection',
         'Eliminar uso de WScript.Shell. Alternativas: chamadas a APIs internas documentadas.'),

        (r'(?i)CreateObject\s*\(\s*["\']Scripting\.FileSystemObject["\']',
         'VBA004', 'FileSystemObject — acesso ao sistema de arquivos', 'MEDIUM', 'CWE-552', 'File Access',
         'Auditar uso de FSO. Restringir a paths específicos e validados. Adicionar logging.'),

        # Download de conteúdo
        (r'(?i)CreateObject\s*\(\s*["\']MSXML2?\.(XMLHTTP|ServerXMLHTTP)',
         'VBA005', 'XMLHTTP — download de conteúdo externo', 'HIGH', 'CWE-494', 'Remote Code Loading',
         'Validar origem (URL whitelist), checksum do conteúdo, e nunca executar conteúdo baixado.'),

        # PowerShell e cmd
        (r'(?i)(powershell|cmd\.exe|wscript|cscript|mshta)',
         'VBA006', 'Referência a intérpretes de sistema', 'HIGH', 'CWE-78', 'Command Injection',
         'Auditoria imediata de todas as ocorrências. Eliminar chamadas a PowerShell/cmd de macros.'),

        # SQL Injection
        (r'(?i)["\']SELECT.*\s*&\s*\w+|["\']INSERT.*\s*&\s*\w+|["\']UPDATE.*\s*&\s*\w+',
         'VBA007', 'SQL concatenado — risco de injection', 'CRITICAL', 'CWE-89', 'SQL Injection',
         'Usar parametrização via ADODB.Command com parâmetros. Nunca concatenar variáveis em SQL.'),

        # Credenciais hardcoded
        (r'(?i)(password|senha|pwd|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
         'VBA008', 'Credencial hardcoded em macro', 'CRITICAL', 'CWE-798', 'Hardcoded Secrets',
         'Remover credencial do código. Usar Windows Credential Manager ou prompt seguro.'),

        # Connection strings com credencial
        (r'(?i)(UID|User ID|PWD|Password)\s*=\s*[^\s;,"\']{2,}',
         'VBA009', 'Credencial em connection string', 'CRITICAL', 'CWE-798', 'Hardcoded Secrets',
         'Usar Windows Authentication (Trusted_Connection=Yes) ou Azure Managed Identity.'),

        # Registro do Windows
        (r'(?i)HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)',
         'VBA010', 'Acesso ao Registro do Windows', 'MEDIUM', 'CWE-284', 'Registry Access',
         'Auditar necessidade de acesso ao registro. Documentar e restringir paths acessados.'),

        # Execução de VBS/scripts baixados
        (r'(?i)(wscript\.exe|mshta\.exe)\s+',
         'VBA011', 'Execução de script via wscript/mshta', 'CRITICAL', 'CWE-78', 'Script Execution',
         'Eliminar execução de scripts externos de dentro de macros.'),
    ]

    VBA_EXTENSIONS = {'.vba', '.bas', '.cls', '.frm', '.vbs', '.xlsm', '.xlsb', '.xltm', '.docm', '.pptm'}

    def scan_file(self, filepath: str) -> List[Finding]:
        findings = []
        ext = Path(filepath).suffix.lower()
        if ext not in self.VBA_EXTENSIONS:
            return findings

        try:
            # Para .xlsm/.docm reais, usaríamos oletools.
            # No MVP, lemos como texto (funciona para .vba/.bas)
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            return findings

        seen = set()
        for i, line in enumerate(lines, 1):
            for pattern, rule_id, rule_name, severity, cwe, category, remediation in self.PATTERNS:
                if re.search(pattern, line):
                    key = (filepath, i, rule_id)
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            file=filepath, line=i,
                            rule_id=rule_id, rule_name=rule_name,
                            severity=severity, category=category,
                            description=f'{rule_name} detectado em macro VBA/Office.',
                            evidence=self._mask_line(line.strip()),
                            cwe=cwe, remediation=remediation, language='VBA'
                        ))
        return findings

    def _mask_line(self, line: str) -> str:
        return re.sub(
            r'((?:password|pwd|secret|token)\s*=\s*["\'])([^"\']{3})[^"\']+(["\'])',
            r'\1\2****\3', line, flags=re.IGNORECASE
        )


# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────

class AutoAuditScanner:
    """Orquestrador principal do scan — percorre diretórios e coordena scanners."""

    PYTHON_EXTENSIONS = {'.py', '.pyw'}
    VBA_EXTENSIONS = {'.vba', '.bas', '.cls', '.frm', '.vbs', '.xlsm', '.xlsb', '.docm', '.pptm'}
    ALL_EXTENSIONS = PYTHON_EXTENSIONS | VBA_EXTENSIONS

    SEVERITY_WEIGHTS = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}

    def __init__(self):
        self.py_scanner = PythonScanner()
        self.vba_scanner = VBAScanner()

    def scan(self, target_path: str) -> ScanResult:
        scan_id = hashlib.md5(f"{target_path}{datetime.now()}".encode()).hexdigest()[:8].upper()
        started_at = datetime.now().isoformat()

        all_findings = []
        files_scanned = 0
        files_skipped = 0
        file_inventory = []

        target = Path(target_path)
        paths = list(target.rglob('*')) if target.is_dir() else [target]

        for path in paths:
            if not path.is_file():
                continue
            ext = path.suffix.lower()
            if ext not in self.ALL_EXTENSIONS:
                continue

            rel_path = str(path)
            language = 'Python' if ext in self.PYTHON_EXTENSIONS else 'VBA'

            try:
                findings = []
                if ext in self.PYTHON_EXTENSIONS:
                    findings = self.py_scanner.scan_file(rel_path)
                elif ext in self.VBA_EXTENSIONS:
                    findings = self.vba_scanner.scan_file(rel_path)

                all_findings.extend(findings)
                files_scanned += 1
                file_inventory.append({
                    'path': rel_path,
                    'language': language,
                    'findings_count': len(findings),
                    'size_bytes': path.stat().st_size,
                    'has_issues': len(findings) > 0
                })
            except Exception:
                files_skipped += 1

        # Counts
        sev_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in all_findings:
            if f.severity in sev_count:
                sev_count[f.severity] += 1

        # Risk Score (0-100)
        raw_score = sum(self.SEVERITY_WEIGHTS[f.severity] for f in all_findings)
        max_possible = max(files_scanned * 50, 1)
        risk_score = min(round((raw_score / max_possible) * 100, 1), 100.0)

        finished_at = datetime.now().isoformat()

        return ScanResult(
            scan_id=scan_id,
            target_path=target_path,
            started_at=started_at,
            finished_at=finished_at,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            total_findings=len(all_findings),
            critical=sev_count['CRITICAL'],
            high=sev_count['HIGH'],
            medium=sev_count['MEDIUM'],
            low=sev_count['LOW'],
            risk_score=risk_score,
            findings=all_findings,
            file_inventory=file_inventory
        )

    def to_json(self, result: ScanResult) -> str:
        d = asdict(result)
        return json.dumps(d, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else './samples'
    
    print(f"\n🔍 AutoAudit Scanner — Setec Consulting Group")
    print(f"   Target: {target}")
    print(f"   Iniciando varredura...\n")

    scanner = AutoAuditScanner()
    result = scanner.scan(target)

    print(f"✅ Scan concluído — ID: {result.scan_id}")
    print(f"   Arquivos analisados: {result.files_scanned}")
    print(f"   Total de findings:   {result.total_findings}")
    print(f"   🔴 Critical: {result.critical}  🟠 High: {result.high}  🟡 Medium: {result.medium}  🔵 Low: {result.low}")
    print(f"   Risk Score: {result.risk_score}/100\n")

    output_path = f"/home/claude/autoaudit/scan_result_{result.scan_id}.json"
    with open(output_path, 'w') as f:
        f.write(scanner.to_json(result))
    print(f"   📄 JSON salvo em: {output_path}")
