# AutoAudit — Commercial Service Model

> Internal guide for Setec Consulting Group sales and delivery teams.

---

## Product-Led Consulting Model

AutoAudit operates on a **diagnose-then-remediate** commercial model:

```
Auditoria (Diagnóstico)    →    Adequação (Remediação)    →    Monitoramento (Recorrência)
    R$ 15k–80k                   Time & Material / Fixo          Serviço Gerenciado
  [Entrada no cliente]          [Receita principal]              [Receita recorrente]
```

The audit is deliberately positioned as a low-friction entry point. The findings report creates urgency and quantifies the remediation scope — making the adequação proposal self-justifying.

---

## Audit Pricing Framework

| Client Profile | Scope | Estimated Price (BRL) |
|---|---|---|
| PME (até 200 FTEs) | até 50 scripts / 5 repos | R$ 15k–25k |
| Mid-market (200–2000 FTEs) | até 200 scripts / 15 repos | R$ 30k–55k |
| Enterprise (2000+ FTEs) | sem limite / todos endpoints | R$ 60k–120k |
| Setor financeiro / regulado | + compliance layer (BACEN, SUSEP) | +20–30% |

**Pricing variables:**
- Number of repositories to scan
- Number of endpoint machines
- Estimated lines of code (proxy: number of scripts × avg size)
- Regulatory requirements (LGPD, BACEN 4658, ANVISA, SOX)
- Time pressure (standard 3–4 weeks vs. accelerated 1 week)

---

## Remediation Phases (Post-Audit)

### Phase 1 — Critical Fix (30 days)
Focus: All CRITICAL findings, especially hardcoded secrets and command injection.

Typical activities:
- Credential rotation + migration to Azure Key Vault / AWS Secrets Manager
- Refactoring `eval()`/`exec()` patterns
- Eliminating `shell=True` in subprocess calls
- Removing/restricting WScript.Shell and Shell() in VBA macros

Effort estimate: 80–200h depending on finding count
Pricing: R$ 40k–100k fixed or R$ 220–280/h T&M

### Phase 2 — Hardening (60 days)
Focus: HIGH and MEDIUM findings, process hardening, developer training.

Typical activities:
- SQL parameterization across all scripts
- SSL certificate configuration
- Macro signing and auto-execution policy (Group Policy)
- Secure deserialization patterns
- Developer secure coding workshop (4h)

Effort estimate: 120–300h
Pricing: R$ 60k–150k fixed

### Phase 3 — Continuous Governance (ongoing)
Focus: Prevention, monitoring, recurring scans.

Deliverables:
- Monthly automated scan + delta report
- Pre-commit hook integration (GitHub Actions / Azure DevOps pipeline)
- Quarterly review meeting
- Prioritized backlog of new findings

Pricing: R$ 3k–12k/month managed service

---

## Target Client Profiles

### Ideal Client Characteristics

**High automation volume** — RPA implemented 3+ years ago, many legacy Excel macros, analyst-written Python scripts proliferating across departments (Finance, Operations, HR).

**Low code security maturity** — No SAST in CI/CD pipeline, no secrets management, developers not trained in secure coding, IT security focused on perimeter (firewall, AV) not code.

**Regulatory pressure** — Under LGPD, BACEN, SUSEP, ANVISA, or SOX requirements that create audit urgency.

**Recent incident or audit finding** — A penetration test, external audit, or internal incident created awareness that automation scripts are a blind spot.

### Best Industries to Target

| Industry | Why AutoAudit Fits | Regulatory Hook |
|---|---|---|
| Insurance | High macro usage, legacy Excel automation, SUSEP pressure | SUSEP Circular 666 |
| Mid-size banks / fintechs | Python scripts for data processing, RPA bots | BACEN Res. 4658 |
| Utilities / Energy | OT/IT convergence, Python on SCADA adjacent systems | LGPD + ANEEL |
| Pharma / MedTech | GxP validated systems, Excel macros in QA processes | ANVISA RDC 658 |
| Large industry (manufacturing) | SAP scripts, Excel-based production control | LGPD + ISO 27001 |

---

## Sales Conversation Guide

### Opening Question
> "Você consegue me dizer exatamente o que os scripts Python e as macros Excel dos seus analistas estão fazendo nos servidores da empresa?"

This question almost always surfaces a "no" — which is the entry point.

### Discovery Questions
1. Quantos scripts Python ou macros VBA/Excel a empresa tem em produção hoje?
2. Esses scripts foram desenvolvidos por TI centralizada ou por analistas de negócio?
3. Existe algum processo de revisão de código para automações (RPA, Python, macros)?
4. Vocês já passaram por auditoria externa de segurança que incluiu análise de scripts?
5. Como a empresa gerencia credenciais de banco de dados usadas em automações?

### Common Objections

**"Nosso time de TI já cuida disso"**
→ "Entendo. Nosso scan em empresas com TI ativa ainda encontra em média 15–20 vulnerabilidades críticas por repositório — principalmente em scripts criados por áreas de negócio fora do controle de TI. Que tal um scan de cortesia em um repositório para calibrarmos?"

**"Não temos orçamento agora"**
→ "A auditoria é o menor investimento desse processo. O que custa caro é descobrir a vulnerabilidade depois de uma violação — multa LGPD pode chegar a 2% do faturamento. O diagnóstico toma 2 semanas e já entrega o mapa completo."

**"Já usamos Snyk / SonarQube"**
→ "Essas ferramentas são excelentes para código de produto. AutoAudit é especializado no gap que elas deixam: scripts Python de analistas e macros VBA/Office — que tipicamente ficam fora do pipeline de CI/CD e não são cobertos por essas plataformas."

---

## Delivery Checklist

### Audit Kickoff
- [ ] Scope definition document signed (repos, endpoints, exclusions)
- [ ] Access credentials / OAuth tokens received securely
- [ ] NDA / confidentiality agreement in place
- [ ] Kick-off call with IT security + automation team leads

### Delivery
- [ ] Automated scan complete (JSON output)
- [ ] Manual review of top 10 CRITICAL findings (validate, remove false positives)
- [ ] Executive report generated (AI-assisted via AutoAudit dashboard)
- [ ] Finding debrief with technical team (2h workshop)
- [ ] Executive presentation (30min, C-level/CISO)
- [ ] Remediation proposal delivered within 5 business days

### Remediation Project
- [ ] Findings prioritized in project backlog
- [ ] Developer assignments defined per finding category
- [ ] Setec consultant assigned per phase
- [ ] Milestone checkpoints (weekly status + rescan of fixed items)
- [ ] Final rescan report (delta: findings before vs. after)
- [ ] Certificate of Adequação issued

---

## Competitive Positioning

| Tool | Scope | Weakness vs. AutoAudit |
|---|---|---|
| Bandit | Python only, no VBA | No Office/VBA support; no dashboard; no AI |
| Semgrep | Multi-language, complex setup | Requires config expertise; no VBA; SaaS cost |
| Snyk | Dependency scanning focus | Doesn't scan script logic; no VBA |
| SonarQube | Enterprise, CI/CD focused | Overkill for script audit; no VBA; expensive |
| Manual audit | Any | 10–20× more expensive; slow; not scalable |

**AutoAudit's differentiation:** purpose-built for the *automation asset* threat surface, with an AI-powered report that immediately translates technical findings into a consulting engagement scope.
