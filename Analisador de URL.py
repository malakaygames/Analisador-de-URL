import tkinter as tk
from tkinter import ttk
import whois
import requests
import socket
from urllib.parse import urlparse

# Função de consulta WHOIS
def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return {"error": str(e)}

# Função de consulta AbuseIPDB
def abuseipdb_lookup(ip_address):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
        headers = {
            "Key": "295ccd73c9572fe3c6fb9db1541e12a3817b193df5233f712055b82d31bdb385e1948920be456ee2",
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers)
        data = response.json()
        return data['data']
    except Exception as e:
        return {"error": str(e)}

# Limpar e simplificar a URL fornecida
def clean_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    if not parsed_url.scheme:
        domain = "http://" + domain  # Adicionar "http://" se faltar
    return domain.split('/')[0]

# Função acionada ao clicar em "Consultar"
def on_submit():
    input_url = entry_url.get()
    output_text.delete(1.0, tk.END)

    # Limpar e processar a URL
    clean_domain = clean_url(input_url)

    # Realizar consulta WHOIS
    whois_data = whois_lookup(clean_domain)
    display_results(whois_data, "WHOIS")

    # Se não houver erro, realizar consulta AbuseIPDB
    if "error" not in whois_data:
        try:
            ip_address = socket.gethostbyname(clean_domain)
            abuseipdb_data = abuseipdb_lookup(ip_address)
            display_results(abuseipdb_data, "AbuseIPDB")
        except Exception as e:
            output_text.insert(tk.END, f"Erro ao obter endereço IP para {clean_domain}: {e}\n")

# Exibir os resultados formatados
def format_value(value):
    """Formata valores, incluindo listas e datas."""
    if isinstance(value, list):
        return ', '.join([str(v) for v in value])
    elif isinstance(value, (str, bytes)):
        return value
    return str(value)

def display_results(data, title):
    output_text.insert(tk.END, f"=== Resultados da Consulta: {title} ===\n")

    if "error" in data:
        output_text.insert(tk.END, f"Erro: {data['error']}\n\n")
        return

    # Criar tabela simulada
    for key, value in data.items():
        output_text.insert(tk.END, f"{key}: {format_value(value)}\n")
    output_text.insert(tk.END, "\n")  # Adiciona espaço entre as seções

# Criar janela principal
root = tk.Tk()
root.title("Consulta de WHOIS e AbuseIPDB")

# Ajuste da aparência da janela
root.geometry("800x600")  # Tamanho maior para acomodar melhor os resultados
root.configure(bg='#e9ebf0')  # Cor de fundo mais profissional

# Estilo de Botões e Entrada
style = ttk.Style()
style.configure("TButton", font=("Arial", 10), padding=10)
style.configure("TEntry", font=("Arial", 12), padding=10)

# Título
title_label = tk.Label(root, text="Consulta de WHOIS e AbuseIPDB", font=("Helvetica", 16, "bold"), bg="#e9ebf0")
title_label.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

# Campo de Entrada para URL
entry_url = ttk.Entry(root, width=70, font=("Arial", 12))
entry_url.grid(row=1, column=0, padx=10, pady=10)

# Botão para Consultar
btn_submit = ttk.Button(root, text="Consultar", command=on_submit)
btn_submit.grid(row=1, column=1, padx=10, pady=10)

# Área de Texto para Resultados
output_text = tk.Text(root, wrap="word", font=("Courier New", 10), bg="#ffffff", fg="#000000", padx=10, pady=10)
output_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

# Ajuste de grid
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(2, weight=1)

# Iniciar loop da janela
root.mainloop()
