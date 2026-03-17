#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# AutoAudit — GitHub Push Script
# Execute este script na raiz do repositório clonado
# ─────────────────────────────────────────────────────────────────
#
# PRÉ-REQUISITOS:
#   1. Git instalado (git --version)
#   2. Repositório criado no GitHub (vazio, sem README)
#   3. Autenticado no GitHub CLI ou via HTTPS token
#
# USO:
#   chmod +x push_to_github.sh
#   ./push_to_github.sh https://github.com/SEU_ORG/autoaudit.git
#
# ─────────────────────────────────────────────────────────────────

REPO_URL=${1:-"https://github.com/SEU_ORG/autoaudit.git"}

echo "🔍 AutoAudit — GitHub Push"
echo "   Destino: $REPO_URL"
echo ""

# Init git
git init
git add .
git commit -m "feat: AutoAudit MVP v1.0

- Scanner engine: Python AST + VBA regex analysis (26 rules)
- React dashboard with Claude AI integration
- Executive report generator via AI
- Demo samples: vulnerable Python + VBA files
- Full documentation: README, ARCHITECTURE, COMMERCIAL
- GitHub Actions CI workflow

Developed by Setec Consulting Group"

# Push
git branch -M main
git remote add origin "$REPO_URL"
git push -u origin main

echo ""
echo "✅ Push concluído!"
echo "   Acesse: $REPO_URL"
