import subprocess
import pickle
import requests
import sqlite3
import os

# Credencial hardcoded - VULNERABILIDADE CRÍTICA
DB_PASSWORD = "admin123"
API_KEY = "sk-prod-xK9mN2pQ7rT4vW1"
SECRET_TOKEN = "bearer_eyJhbGciOiJIUzI1NiJ9.payload.sig"

def executar_relatorio(nome_arquivo):
    # Command injection via shell=True - CRÍTICO
    resultado = subprocess.run(f"python {nome_arquivo}", shell=True, capture_output=True)
    return resultado.stdout

def processar_dados(user_input):
    # eval com input externo - CRÍTICO
    resultado = eval(user_input)
    return resultado

def carregar_cache(arquivo_cache):
    # Desserialização insegura - ALTO
    with open(arquivo_cache, 'rb') as f:
        dados = pickle.load(f)
    return dados

def consultar_bd(nome_usuario):
    conn = sqlite3.connect("dados.db")
    cursor = conn.cursor()
    # SQL injection - CRÍTICO
    query = "SELECT * FROM usuarios WHERE nome = '" + nome_usuario + "'"
    cursor.execute(query)
    return cursor.fetchall()

def baixar_relatorio(url):
    # SSL verification disabled - MÉDIO
    response = requests.get(url, verify=False)
    return response.content

def executar_comando(cmd):
    # os.system com variável dinâmica - ALTO
    os.system(cmd)

def processar_expressao(expr):
    # exec com input - CRÍTICO
    exec(expr)
