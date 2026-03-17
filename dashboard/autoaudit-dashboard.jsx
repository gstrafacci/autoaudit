import { useState, useEffect, useRef } from "react";

// ─── SCAN DATA (resultado real do engine Python) ───────────────────────────
const SCAN_DATA = {
  scan_id: "3B271E2A",
  target_path: "samples/",
  started_at: "2026-03-16T18:45:59.193135",
  finished_at: "2026-03-16T18:45:59.199544",
  files_scanned: 2,
  files_skipped: 0,
  total_findings: 23,
  critical: 12,
  high: 9,
  medium: 2,
  low: 0,
  risk_score: 100.0,
  findings: [
    { file: "samples/macro_legada.vba", line: 8, rule_id: "VBA001", rule_name: "Macro de auto-execução", severity: "HIGH", category: "Execução Automática", description: "Macro de auto-execução detectado em macro VBA/Office.", evidence: "Private Sub Workbook_Open()", cwe: "CWE-284", remediation: "Remover ou auditar macros com auto-execução. Implementar assinatura digital de macros.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 17, rule_id: "VBA003", rule_name: "WScript.Shell — execução de comandos", severity: "CRITICAL", category: "Command Injection", description: "WScript.Shell — execução de comandos detectado em macro VBA/Office.", evidence: 'Set oShell = CreateObject("WScript.Shell")', cwe: "CWE-78", remediation: "Eliminar uso de WScript.Shell. Alternativas: chamadas a APIs internas documentadas.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 18, rule_id: "VBA006", rule_name: "Referência a intérpretes de sistema", severity: "HIGH", category: "Command Injection", description: "Referência a intérpretes de sistema detectado em macro VBA/Office.", evidence: 'oShell.Run "cmd.exe /c ipconfig > C:\\temp\\rede.txt", 0, True', cwe: "CWE-78", remediation: "Auditoria imediata de todas as ocorrências. Eliminar chamadas a PowerShell/cmd de macros.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 21, rule_id: "VBA006", rule_name: "Referência a intérpretes de sistema", severity: "HIGH", category: "Command Injection", description: "Referência a intérpretes de sistema detectado em macro VBA/Office.", evidence: 'Shell "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\sync.ps1"', cwe: "CWE-78", remediation: "Auditoria imediata de todas as ocorrências. Eliminar chamadas a PowerShell/cmd de macros.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 29, rule_id: "VBA005", rule_name: "XMLHTTP — download de conteúdo externo", severity: "HIGH", category: "Remote Code Loading", description: "XMLHTTP — download de conteúdo externo detectado em macro VBA/Office.", evidence: 'Set oHTTP = CreateObject("MSXML2.XMLHTTP")', cwe: "CWE-494", remediation: "Validar origem (URL whitelist), checksum do conteúdo, e nunca executar conteúdo baixado.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 40, rule_id: "VBA004", rule_name: "FileSystemObject — acesso ao sistema de arquivos", severity: "MEDIUM", category: "File Access", description: "FileSystemObject — acesso ao sistema de arquivos detectado.", evidence: 'Set oFSO = CreateObject("Scripting.FileSystemObject")', cwe: "CWE-552", remediation: "Auditar uso de FSO. Restringir a paths específicos e validados. Adicionar logging.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 46, rule_id: "VBA011", rule_name: "Execução de script via wscript/mshta", severity: "CRITICAL", category: "Script Execution", description: "Execução de script via wscript/mshta detectado em macro VBA/Office.", evidence: 'Shell "wscript.exe C:\\temp\\update.vbs"', cwe: "CWE-78", remediation: "Eliminar execução de scripts externos de dentro de macros.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 52, rule_id: "VBA007", rule_name: "SQL concatenado — risco de injection", severity: "CRITICAL", category: "SQL Injection", description: "SQL concatenado — risco de injection detectado em macro VBA/Office.", evidence: "sQuery = \"SELECT * FROM clientes WHERE nome = '\" & sNomeUsuario & \"'\"", cwe: "CWE-89", remediation: "Usar parametrização via ADODB.Command com parâmetros. Nunca concatenar variáveis em SQL.", language: "VBA" },
    { file: "samples/macro_legada.vba", line: 56, rule_id: "VBA009", rule_name: "Credencial em connection string", severity: "CRITICAL", category: "Hardcoded Secrets", description: "Credencial em connection string detectado em macro VBA/Office.", evidence: 'sConnStr = "Provider=SQLOLEDB;Server=srv-prod;Database=dados;UID=sa;PWD=" & DB_PASSWORD', cwe: "CWE-798", remediation: "Usar Windows Authentication (Trusted_Connection=Yes) ou Azure Managed Identity.", language: "VBA" },
    { file: "samples/analise_dados.py", line: 8, rule_id: "PY014", rule_name: "Credencial/segredo hardcoded", severity: "CRITICAL", category: "Hardcoded Secrets", description: "Credencial ou segredo encontrado diretamente no código-fonte.", evidence: 'DB_PASSWORD = "admi****"', cwe: "CWE-798", remediation: "Mover credenciais para variáveis de ambiente ou cofre de segredos (Vault, Azure Key Vault, AWS Secrets Manager).", language: "Python" },
    { file: "samples/analise_dados.py", line: 9, rule_id: "PY015", rule_name: "Token/API Key exposto no código", severity: "CRITICAL", category: "Hardcoded Secrets", description: "Credencial ou segredo encontrado diretamente no código-fonte.", evidence: 'API_KEY = "sk-p****"', cwe: "CWE-798", remediation: "Revogar token imediatamente. Usar variáveis de ambiente ou secrets manager.", language: "Python" },
    { file: "samples/analise_dados.py", line: 14, rule_id: "PY004", rule_name: "subprocess com shell=True", severity: "CRITICAL", category: "Command Injection", description: "Execução de comandos do sistema com entrada potencialmente não sanitizada.", evidence: 'resultado = subprocess.run(f"python {nome_arquivo}", shell=True, capture_output=True)', cwe: "CWE-78", remediation: "Remover shell=True. Passar argumentos como lista. Sanitizar todos os inputs.", language: "Python" },
    { file: "samples/analise_dados.py", line: 19, rule_id: "PY001", rule_name: "Uso de eval() com input externo", severity: "CRITICAL", category: "Code Injection", description: "Função perigosa eval() detectada — pode executar código arbitrário.", evidence: "resultado = eval(user_input)", cwe: "CWE-78", remediation: "Substituir eval() por ast.literal_eval() ou lógica explícita. Nunca avaliar input de usuário.", language: "Python" },
    { file: "samples/analise_dados.py", line: 25, rule_id: "PY007", rule_name: "Desserialização insegura com pickle", severity: "HIGH", category: "Insecure Deserialization", description: "Desserialização de dados de fonte não confiável pode executar código arbitrário.", evidence: "dados = pickle.load(f)", cwe: "CWE-502", remediation: "Nunca usar pickle com dados de fontes externas. Usar JSON ou protobuf validado.", language: "Python" },
    { file: "samples/analise_dados.py", line: 31, rule_id: "PY013", rule_name: "SQL injection — concatenação de string", severity: "CRITICAL", category: "SQL Injection", description: "Construção insegura de query SQL — risco de SQL Injection.", evidence: "query = \"SELECT * FROM usuarios WHERE nome = '\" + nome_usuario + \"'\"", cwe: "CWE-89", remediation: "Usar parametrização de queries: cursor.execute(sql, params). Nunca concatenar input do usuário.", language: "Python" },
    { file: "samples/analise_dados.py", line: 38, rule_id: "PY010", rule_name: "Verificação SSL desabilitada", severity: "MEDIUM", category: "Cryptography", description: "Configuração criptográfica insegura detectada.", evidence: "response = requests.get(url, verify=False)", cwe: "CWE-295", remediation: "Remover verify=False. Configurar bundle de certificados correto.", language: "Python" },
    { file: "samples/analise_dados.py", line: 43, rule_id: "PY005", rule_name: "os.system() com argumento dinâmico", severity: "HIGH", category: "Command Injection", description: "Execução de comandos do sistema com entrada potencialmente não sanitizada.", evidence: "os.system(cmd)", cwe: "CWE-78", remediation: "Substituir os.system() por subprocess com lista de argumentos e sem shell=True.", language: "Python" },
    { file: "samples/analise_dados.py", line: 47, rule_id: "PY002", rule_name: "Uso de exec() dinâmico", severity: "CRITICAL", category: "Code Injection", description: "Função perigosa exec() detectada — pode executar código arbitrário.", evidence: "exec(expr)", cwe: "CWE-78", remediation: "Eliminar exec() dinâmico. Refatorar para funções explícitas e controladas.", language: "Python" },
  ],
  file_inventory: [
    { path: "samples/macro_legada.vba", language: "VBA", findings_count: 12, size_bytes: 1769, has_issues: true },
    { path: "samples/analise_dados.py", language: "Python", findings_count: 11, size_bytes: 1317, has_issues: true },
  ]
};

// ─── SEVERITY CONFIG ───────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", label: "CRITICAL", dot: "●" },
  HIGH:     { color: "#ff9500", bg: "rgba(255,149,0,0.12)",  label: "HIGH",     dot: "●" },
  MEDIUM:   { color: "#ffd60a", bg: "rgba(255,214,10,0.12)", label: "MEDIUM",   dot: "●" },
  LOW:      { color: "#30d158", bg: "rgba(48,209,88,0.12)",  label: "LOW",      dot: "●" },
  INFO:     { color: "#636366", bg: "rgba(99,99,102,0.12)",  label: "INFO",     dot: "●" },
};

const CATEGORY_ICONS = {
  "Command Injection": "⚡",
  "Code Injection": "💉",
  "SQL Injection": "🗄️",
  "Hardcoded Secrets": "🔑",
  "Insecure Deserialization": "📦",
  "Cryptography": "🔓",
  "Remote Code Loading": "📡",
  "Script Execution": "⚙️",
  "File Access": "📁",
  "Execução Automática": "🔄",
};

// ─── CLAUDE AI ANALYSIS ────────────────────────────────────────────────────
async function callClaude(prompt) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      system: `Você é o AutoAudit AI da Setec Consulting Group — especialista em segurança de código Python e VBA corporativo.
Responda sempre em português brasileiro, de forma técnica e objetiva.
Seja direto: sem introduções genéricas, sem "claro!", sem elogios.
Estruture com •bullets ou numeração quando listar itens.
Foque em: impacto de negócio, risco real, remediação prática.`,
      messages: [{ role: "user", content: prompt }]
    })
  });
  const data = await res.json();
  return data.content?.[0]?.text || "Erro ao chamar a API.";
}

// ─── COMPONENTS ────────────────────────────────────────────────────────────

function RiskGauge({ score }) {
  const r = 54, cx = 64, cy = 64;
  const circ = 2 * Math.PI * r;
  const fill = (score / 100) * circ;
  const color = score >= 75 ? "#ff2d55" : score >= 40 ? "#ff9500" : "#30d158";
  return (
    <div style={{ position: "relative", width: 128, height: 128 }}>
      <svg width="128" height="128" style={{ transform: "rotate(-90deg)" }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${fill} ${circ - fill}`}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: "stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1)" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <span style={{ fontSize: 26, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace" }}>{score}</span>
        <span style={{ fontSize: 10, color: "#636366", letterSpacing: 2, fontFamily: "monospace" }}>RISK SCORE</span>
      </div>
    </div>
  );
}

function ScanningAnimation({ onComplete }) {
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("Iniciando varredura...");
  const phases = [
    "Mapeando sistema de arquivos...",
    "Analisando scripts Python...",
    "Parseando AST — árvore sintática...",
    "Verificando padrões VBA/Office...",
    "Aplicando rule engine — 26 regras...",
    "Calculando risk score...",
    "Gerando relatório de findings...",
    "Scan concluído.",
  ];
  useEffect(() => {
    let p = 0;
    const interval = setInterval(() => {
      p += Math.random() * 18 + 5;
      if (p >= 100) { p = 100; clearInterval(interval); setTimeout(onComplete, 600); }
      setProgress(Math.min(p, 100));
      setPhase(phases[Math.min(Math.floor(p / 14), phases.length - 1)]);
    }, 220);
    return () => clearInterval(interval);
  }, []);
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100vh", background: "#0a0a0f", gap: 32 }}>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", color: "#ff6b00", fontSize: 22, fontWeight: 700, letterSpacing: 3 }}>
        AUTO<span style={{ color: "#fff" }}>AUDIT</span>
      </div>
      <div style={{ width: 380, background: "rgba(255,255,255,0.04)", borderRadius: 4, overflow: "hidden", border: "1px solid rgba(255,255,255,0.08)" }}>
        <div style={{ height: 4, background: "#ff6b00", width: `${progress}%`, transition: "width 0.2s ease", boxShadow: "0 0 12px #ff6b00" }} />
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", color: "#636366", fontSize: 12, letterSpacing: 1 }}>
        <span style={{ color: "#30d158" }}>▶</span> {phase}
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", color: "#ff6b00", fontSize: 11 }}>{Math.floor(progress)}%</div>
    </div>
  );
}

function FindingCard({ finding, onAskAI }) {
  const sev = SEV[finding.severity] || SEV.INFO;
  const icon = CATEGORY_ICONS[finding.category] || "⚠️";
  return (
    <div style={{
      background: "rgba(255,255,255,0.028)", border: `1px solid rgba(255,255,255,0.07)`,
      borderLeft: `3px solid ${sev.color}`, borderRadius: 8, padding: "14px 16px",
      marginBottom: 8, transition: "background 0.15s",
    }}
      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.05)"}
      onMouseLeave={e => e.currentTarget.style.background = "rgba(255,255,255,0.028)"}
    >
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 13 }}>{icon}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: sev.color, fontWeight: 700,
              background: sev.bg, padding: "2px 8px", borderRadius: 3 }}>{finding.severity}</span>
            <span style={{ fontFamily: "monospace", fontSize: 10, color: "#636366" }}>{finding.rule_id}</span>
            <span style={{ fontFamily: "monospace", fontSize: 10, color: "#8e8e93" }}>•</span>
            <span style={{ fontFamily: "monospace", fontSize: 10, color: "#48484a" }}>
              {finding.language === "Python" ? "🐍" : "📊"} {finding.language}
            </span>
          </div>
          <div style={{ color: "#e5e5ea", fontSize: 13, fontWeight: 600, marginBottom: 3 }}>{finding.rule_name}</div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#636366", marginBottom: 6 }}>
            📄 {finding.file.split("/").pop()} · linha {finding.line} · {finding.cwe}
          </div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 11, background: "rgba(0,0,0,0.4)",
            padding: "6px 10px", borderRadius: 4, color: "#ff9f0a", border: "1px solid rgba(255,255,255,0.05)",
            wordBreak: "break-all", marginBottom: 6
          }}>
            {finding.evidence}
          </div>
          <div style={{ fontSize: 11, color: "#8e8e93" }}>
            <span style={{ color: "#30d158" }}>→ </span>{finding.remediation}
          </div>
        </div>
        <button onClick={() => onAskAI(finding)}
          style={{ background: "rgba(255,107,0,0.12)", border: "1px solid rgba(255,107,0,0.3)",
            color: "#ff6b00", padding: "6px 12px", borderRadius: 6, fontSize: 11, cursor: "pointer",
            fontFamily: "monospace", whiteSpace: "nowrap", flexShrink: 0,
            fontWeight: 600, letterSpacing: 0.5 }}>
          🤖 Analisar
        </button>
      </div>
    </div>
  );
}

function AIPanel({ finding, onClose }) {
  const [response, setResponse] = useState("");
  const [loading, setLoading] = useState(true);
  const [question, setQuestion] = useState("");
  const [chatHistory, setChatHistory] = useState([]);

  useEffect(() => {
    const prompt = `Analise esta vulnerabilidade encontrada em auditoria de código corporativo:

ARQUIVO: ${finding.file}
LINHA: ${finding.line}
REGRA: ${finding.rule_name} (${finding.rule_id})
SEVERIDADE: ${finding.severity}
CATEGORIA: ${finding.category}
CWE: ${finding.cwe}
EVIDÊNCIA NO CÓDIGO: ${finding.evidence}

Forneça:
1. Impacto real de negócio se explorada (2-3 linhas)
2. Cenário de ataque concreto (como um atacante exploraria isso)
3. Remediação passo a passo (código corrigido se aplicável)
4. Estimativa de esforço de correção (horas)
5. Prioridade de correção em um plano de adequação`;

    callClaude(prompt).then(r => { setResponse(r); setLoading(false); });
  }, [finding]);

  const askFollowUp = async () => {
    if (!question.trim()) return;
    const q = question;
    setQuestion("");
    setChatHistory(h => [...h, { role: "user", text: q }]);
    const context = `Contexto: vulnerabilidade ${finding.rule_name} no arquivo ${finding.file}.\n\nPergunta: ${q}`;
    const answer = await callClaude(context);
    setChatHistory(h => [...h, { role: "ai", text: answer }]);
  };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div style={{ background: "#111118", border: "1px solid rgba(255,107,0,0.3)", borderRadius: 12,
        width: "100%", maxWidth: 680, maxHeight: "85vh", display: "flex", flexDirection: "column",
        boxShadow: "0 0 60px rgba(255,107,0,0.15)" }}>
        {/* Header */}
        <div style={{ padding: "16px 20px", borderBottom: "1px solid rgba(255,255,255,0.07)",
          display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ color: "#ff6b00", fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: 2, marginBottom: 2 }}>
              🤖 AUTOAUDIT AI — ANÁLISE
            </div>
            <div style={{ color: "#e5e5ea", fontSize: 13, fontWeight: 600 }}>{finding.rule_name}</div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#636366", fontSize: 20, cursor: "pointer" }}>✕</button>
        </div>
        {/* Evidence */}
        <div style={{ padding: "10px 20px", background: "rgba(0,0,0,0.3)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#ff9f0a" }}>{finding.evidence}</span>
        </div>
        {/* AI Response */}
        <div style={{ flex: 1, overflowY: "auto", padding: 20 }}>
          {loading ? (
            <div style={{ display: "flex", alignItems: "center", gap: 10, color: "#636366", fontFamily: "monospace", fontSize: 13 }}>
              <div style={{ width: 8, height: 8, background: "#ff6b00", borderRadius: "50%",
                animation: "pulse 1s infinite" }} />
              Analisando vulnerabilidade...
            </div>
          ) : (
            <div style={{ color: "#c7c7cc", fontSize: 13, lineHeight: 1.7, whiteSpace: "pre-wrap", fontFamily: "system-ui" }}>
              {response}
            </div>
          )}
          {chatHistory.map((msg, i) => (
            <div key={i} style={{ marginTop: 16, padding: "10px 14px", borderRadius: 8,
              background: msg.role === "user" ? "rgba(255,107,0,0.08)" : "rgba(255,255,255,0.03)",
              borderLeft: msg.role === "user" ? "2px solid #ff6b00" : "2px solid #636366" }}>
              <div style={{ fontSize: 10, color: msg.role === "user" ? "#ff6b00" : "#48484a", fontFamily: "monospace", marginBottom: 4, fontWeight: 700 }}>
                {msg.role === "user" ? "VOCÊ" : "AI"}
              </div>
              <div style={{ color: "#c7c7cc", fontSize: 13, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>{msg.text}</div>
            </div>
          ))}
        </div>
        {/* Follow-up input */}
        <div style={{ padding: 16, borderTop: "1px solid rgba(255,255,255,0.07)", display: "flex", gap: 8 }}>
          <input value={question} onChange={e => setQuestion(e.target.value)}
            onKeyDown={e => e.key === "Enter" && askFollowUp()}
            placeholder="Pergunte sobre esta vulnerabilidade..."
            style={{ flex: 1, background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 8, padding: "10px 14px", color: "#e5e5ea", fontSize: 13,
              fontFamily: "system-ui", outline: "none" }} />
          <button onClick={askFollowUp}
            style={{ background: "#ff6b00", border: "none", borderRadius: 8, padding: "10px 16px",
              color: "#fff", fontSize: 13, cursor: "pointer", fontWeight: 700 }}>→</button>
        </div>
      </div>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }`}</style>
    </div>
  );
}

// ─── MAIN APP ──────────────────────────────────────────────────────────────
export default function AutoAuditDashboard() {
  const [phase, setPhase] = useState("scanning"); // scanning | dashboard
  const [activeTab, setActiveTab] = useState("findings");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [langFilter, setLangFilter] = useState("ALL");
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [executiveSummary, setExecutiveSummary] = useState("");
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  const data = SCAN_DATA;
  const findings = data.findings.filter(f => {
    if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
    if (langFilter !== "ALL" && f.language !== langFilter) return false;
    if (searchTerm && !f.rule_name.toLowerCase().includes(searchTerm.toLowerCase()) &&
      !f.category.toLowerCase().includes(searchTerm.toLowerCase()) &&
      !f.evidence.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const categories = [...new Set(data.findings.map(f => f.category))];
  const catCounts = categories.map(c => ({ name: c, count: data.findings.filter(f => f.category === c).length }))
    .sort((a, b) => b.count - a.count);

  const generateExecutiveSummary = async () => {
    setSummaryLoading(true);
    setActiveTab("executive");
    const prompt = `Gere um relatório executivo de auditoria de segurança para apresentação ao C-level/board.

DADOS DO SCAN:
- Scan ID: ${data.scan_id}
- Alvo: ${data.target_path}
- Arquivos analisados: ${data.files_scanned}
- Total de findings: ${data.total_findings}
- Critical: ${data.critical} | High: ${data.high} | Medium: ${data.medium} | Low: ${data.low}
- Risk Score: ${data.risk_score}/100

CATEGORIAS DETECTADAS:
${catCounts.map(c => `• ${c.name}: ${c.count} ocorrências`).join("\n")}

TOP VULNERABILIDADES:
${data.findings.filter(f => f.severity === "CRITICAL").slice(0,5).map(f => `• ${f.rule_name} (${f.file}:${f.line})`).join("\n")}

Estruture o relatório com:
1. DIAGNÓSTICO EXECUTIVO (3-4 linhas de impacto real)
2. SUPERFÍCIE DE RISCO (o que está exposto e por quê importa)
3. TOP 3 RISCOS CRÍTICOS (com impacto de negócio específico)
4. PLANO DE ADEQUAÇÃO RECOMENDADO (Fase 1: 30 dias, Fase 2: 60 dias, Fase 3: ongoing)
5. ESTIMATIVA DE ESFORÇO E INVESTIMENTO (horas-consultor, referências de mercado BR)
6. NEXT STEP (ação imediata recomendada)

Tom: técnico mas acessível para CEO/CFO/CISO. Direto ao ponto. Use dados numéricos.`;

    const result = await callClaude(prompt);
    setExecutiveSummary(result);
    setSummaryLoading(false);
  };

  if (phase === "scanning") {
    return <ScanningAnimation onComplete={() => setPhase("dashboard")} />;
  }

  const tabs = [
    { id: "findings", label: `Findings (${data.total_findings})` },
    { id: "files", label: `Arquivos (${data.files_scanned})` },
    { id: "categories", label: "Categorias" },
    { id: "executive", label: "🤖 Relatório Executivo" },
  ];

  return (
    <div style={{ minHeight: "100vh", background: "#0a0a0f", color: "#e5e5ea", fontFamily: "system-ui, -apple-system, sans-serif" }}>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #2c2c2e; border-radius: 4px; }
        input::placeholder { color: #3a3a3c; }
      `}</style>

      {/* TOP BAR */}
      <div style={{ background: "rgba(0,0,0,0.6)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        padding: "0 24px", display: "flex", alignItems: "center", height: 52, gap: 16, backdropFilter: "blur(10px)" }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 800, fontSize: 15, letterSpacing: 1 }}>
          <span style={{ color: "#ff6b00" }}>AUTO</span><span style={{ color: "#fff" }}>AUDIT</span>
          <span style={{ color: "#3a3a3c", fontWeight: 400, fontSize: 11, marginLeft: 8 }}>by Setec Consulting Group</span>
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ fontFamily: "monospace", fontSize: 11, color: "#48484a" }}>
          SCAN #{data.scan_id} · {new Date(data.started_at).toLocaleString("pt-BR")}
        </div>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#30d158",
          boxShadow: "0 0 6px #30d158" }} />
        <span style={{ fontFamily: "monospace", fontSize: 11, color: "#30d158" }}>SCAN CONCLUÍDO</span>
      </div>

      {/* HERO METRICS */}
      <div style={{ padding: "24px 24px 0", display: "grid",
        gridTemplateColumns: "auto 1fr 1fr 1fr 1fr 1fr", gap: 16, alignItems: "stretch" }}>
        {/* Gauge */}
        <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 12, padding: "20px 28px", display: "flex", flexDirection: "column",
          alignItems: "center", gap: 8 }}>
          <RiskGauge score={data.risk_score} />
          <div style={{ fontFamily: "monospace", fontSize: 10, color: "#ff2d55", letterSpacing: 2, fontWeight: 700 }}>
            RISCO CRÍTICO
          </div>
        </div>
        {/* Stat cards */}
        {[
          { label: "CRITICAL", value: data.critical, color: "#ff2d55", icon: "🔴" },
          { label: "HIGH", value: data.high, color: "#ff9500", icon: "🟠" },
          { label: "MEDIUM", value: data.medium, color: "#ffd60a", icon: "🟡" },
          { label: "ARQUIVOS", value: data.files_scanned, color: "#636366", icon: "📁" },
          { label: "TOTAL", value: data.total_findings, color: "#ff6b00", icon: "⚠️" },
        ].map(s => (
          <div key={s.label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
            <div style={{ fontSize: 11, color: "#48484a", fontFamily: "monospace", letterSpacing: 1.5, fontWeight: 700 }}>
              {s.icon} {s.label}
            </div>
            <div style={{ fontSize: 42, fontWeight: 800, color: s.color, lineHeight: 1,
              fontFamily: "'JetBrains Mono', monospace",
              textShadow: `0 0 20px ${s.color}55` }}>
              {s.value}
            </div>
          </div>
        ))}
      </div>

      {/* TABS */}
      <div style={{ padding: "20px 24px 0", display: "flex", gap: 4, borderBottom: "1px solid rgba(255,255,255,0.06)", marginTop: 4 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => t.id === "executive" ? generateExecutiveSummary() : setActiveTab(t.id)}
            style={{ background: activeTab === t.id ? "rgba(255,107,0,0.12)" : "none",
              border: activeTab === t.id ? "1px solid rgba(255,107,0,0.3)" : "1px solid transparent",
              borderBottom: "none", color: activeTab === t.id ? "#ff6b00" : "#636366",
              padding: "8px 18px", borderRadius: "6px 6px 0 0", cursor: "pointer",
              fontSize: 12, fontFamily: "monospace", fontWeight: activeTab === t.id ? 700 : 400,
              letterSpacing: 0.5 }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* CONTENT */}
      <div style={{ padding: 24 }}>

        {/* FINDINGS TAB */}
        {activeTab === "findings" && (
          <div>
            {/* Filters */}
            <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
              <input value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
                placeholder="🔍  Buscar finding..."
                style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 8, padding: "8px 14px", color: "#e5e5ea", fontSize: 13, width: 240, outline: "none" }} />
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                <button key={s} onClick={() => setSeverityFilter(s)}
                  style={{ background: severityFilter === s ? (SEV[s]?.bg || "rgba(255,107,0,0.15)") : "rgba(255,255,255,0.04)",
                    border: `1px solid ${severityFilter === s ? (SEV[s]?.color || "#ff6b00") : "rgba(255,255,255,0.08)"}`,
                    color: severityFilter === s ? (SEV[s]?.color || "#ff6b00") : "#636366",
                    padding: "7px 14px", borderRadius: 8, cursor: "pointer", fontSize: 11,
                    fontFamily: "monospace", fontWeight: 700, letterSpacing: 0.5 }}>
                  {s}
                </button>
              ))}
              <div style={{ borderLeft: "1px solid rgba(255,255,255,0.08)", margin: "0 4px" }} />
              {["ALL", "Python", "VBA"].map(l => (
                <button key={l} onClick={() => setLangFilter(l)}
                  style={{ background: langFilter === l ? "rgba(255,107,0,0.15)" : "rgba(255,255,255,0.04)",
                    border: `1px solid ${langFilter === l ? "#ff6b00" : "rgba(255,255,255,0.08)"}`,
                    color: langFilter === l ? "#ff6b00" : "#636366",
                    padding: "7px 14px", borderRadius: 8, cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}>
                  {l === "Python" ? "🐍 " : l === "VBA" ? "📊 " : ""}{l}
                </button>
              ))}
              <div style={{ marginLeft: "auto", color: "#48484a", fontFamily: "monospace", fontSize: 11, alignSelf: "center" }}>
                {findings.length} resultados
              </div>
            </div>
            {findings.map((f, i) => (
              <FindingCard key={i} finding={f} onAskAI={setSelectedFinding} />
            ))}
          </div>
        )}

        {/* FILES TAB */}
        {activeTab === "files" && (
          <div>
            {data.file_inventory.map((file, i) => (
              <div key={i} style={{ background: "rgba(255,255,255,0.028)", border: "1px solid rgba(255,255,255,0.07)",
                borderRadius: 10, padding: "16px 20px", marginBottom: 10,
                borderLeft: `3px solid ${file.has_issues ? "#ff2d55" : "#30d158"}` }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#e5e5ea", marginBottom: 4 }}>
                      {file.language === "Python" ? "🐍" : "📊"} {file.path}
                    </div>
                    <div style={{ fontFamily: "monospace", fontSize: 11, color: "#48484a" }}>
                      {file.language} · {(file.size_bytes / 1024).toFixed(1)} KB
                    </div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 28, fontWeight: 800, color: file.findings_count > 0 ? "#ff2d55" : "#30d158",
                      fontFamily: "'JetBrains Mono', monospace" }}>{file.findings_count}</div>
                    <div style={{ fontFamily: "monospace", fontSize: 10, color: "#636366" }}>findings</div>
                  </div>
                </div>
                {/* Mini severity breakdown for this file */}
                <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => {
                    const count = data.findings.filter(f => f.file === file.path && f.severity === sev).length;
                    if (!count) return null;
                    return (
                      <span key={sev} style={{ fontFamily: "monospace", fontSize: 10, fontWeight: 700,
                        color: SEV[sev].color, background: SEV[sev].bg, padding: "2px 8px", borderRadius: 4 }}>
                        {sev}: {count}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* CATEGORIES TAB */}
        {activeTab === "categories" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 12 }}>
            {catCounts.map(cat => {
              const critCount = data.findings.filter(f => f.category === cat.name && f.severity === "CRITICAL").length;
              const highCount = data.findings.filter(f => f.category === cat.name && f.severity === "HIGH").length;
              const icon = CATEGORY_ICONS[cat.name] || "⚠️";
              return (
                <div key={cat.name} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
                  borderRadius: 10, padding: 18 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{ fontSize: 22 }}>{icon}</span>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: "#e5e5ea" }}>{cat.name}</div>
                        <div style={{ fontFamily: "monospace", fontSize: 10, color: "#48484a" }}>{cat.count} findings</div>
                      </div>
                    </div>
                    <div style={{ fontSize: 32, fontWeight: 800, color: critCount > 0 ? "#ff2d55" : "#ff9500",
                      fontFamily: "'JetBrains Mono', monospace" }}>{cat.count}</div>
                  </div>
                  <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${(cat.count / data.total_findings) * 100}%`,
                      background: critCount > 0 ? "#ff2d55" : "#ff9500", borderRadius: 2,
                      boxShadow: `0 0 8px ${critCount > 0 ? "#ff2d55" : "#ff9500"}` }} />
                  </div>
                  <div style={{ marginTop: 8, display: "flex", gap: 6 }}>
                    {critCount > 0 && <span style={{ fontSize: 10, fontFamily: "monospace", color: "#ff2d55",
                      background: "rgba(255,45,85,0.12)", padding: "2px 8px", borderRadius: 4, fontWeight: 700 }}>
                      {critCount} CRITICAL</span>}
                    {highCount > 0 && <span style={{ fontSize: 10, fontFamily: "monospace", color: "#ff9500",
                      background: "rgba(255,149,0,0.12)", padding: "2px 8px", borderRadius: 4, fontWeight: 700 }}>
                      {highCount} HIGH</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* EXECUTIVE REPORT TAB */}
        {activeTab === "executive" && (
          <div style={{ maxWidth: 760 }}>
            <div style={{ background: "rgba(255,107,0,0.06)", border: "1px solid rgba(255,107,0,0.2)",
              borderRadius: 10, padding: "14px 18px", marginBottom: 20,
              display: "flex", alignItems: "center", gap: 12 }}>
              <span style={{ fontSize: 20 }}>🤖</span>
              <div>
                <div style={{ color: "#ff6b00", fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1 }}>
                  AUTOAUDIT AI — RELATÓRIO EXECUTIVO
                </div>
                <div style={{ color: "#8e8e93", fontSize: 12 }}>
                  Gerado por Claude AI · Baseado nos {data.total_findings} findings do scan #{data.scan_id}
                </div>
              </div>
            </div>
            {summaryLoading ? (
              <div style={{ display: "flex", alignItems: "center", gap: 12, color: "#636366", fontFamily: "monospace", fontSize: 13, padding: 20 }}>
                <div style={{ width: 10, height: 10, background: "#ff6b00", borderRadius: "50%",
                  animation: "pulse 1s infinite" }} />
                Claude AI está gerando o relatório executivo...
              </div>
            ) : (
              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
                borderRadius: 10, padding: 24, color: "#c7c7cc", fontSize: 14, lineHeight: 1.8,
                whiteSpace: "pre-wrap", fontFamily: "system-ui" }}>
                {executiveSummary}
              </div>
            )}
          </div>
        )}
      </div>

      {/* AI PANEL MODAL */}
      {selectedFinding && (
        <AIPanel finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
