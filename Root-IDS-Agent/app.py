from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import subprocess
import platform
import socket

app = FastAPI(title="RootIDS Desktop Agent", version="1.0")

# Criamos uma pasta temporal para templates HTML simples
import os
os.makedirs("templates", exist_ok=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <title>RootIDS - Painel de Monitorização</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f9; margin: 0; padding: 20px; }
        .container { max-width: 700px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); margin: auto; }
        h1 { color: #333; text-align: center; }
        form { margin-bottom: 20px; display: flex; gap: 10px; }
        input[type="text"] { flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px; }
        button { padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #0056b3; }
        .results { background: #e9ecef; padding: 15px; border-radius: 4px; white-space: pre-wrap; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RootIDS - Inspecionar Dispositivo/Rede</h1>
        <form method="post" action="/scan">
            <input type="text" name="target_ip" placeholder="Ex: 192.168.1.100 ou 192.168.1.0/24" value="{{ target_ip }}" required>
            <button type="submit">Verificar Estado</button>
        </form>
        
        {% if result %}
            <h3>Resultado para: {{ target_ip }}</h3>
            <div class="results">{{ result }}</div>
        {% endif %}
    </div>
</body>
</html>
"""

with open("templates/index.html", "w", encoding="utf-8") as f:
    f.write(HTML_TEMPLATE)

templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
  return templates.TemplateResponse(
      request=request,
      name="index.html",
      context={
          "request": request,
          "result": None,
          "target_ip": "",
      },
  )

@app.post("/scan", response_class=HTMLResponse)
async def scan_target(request: Request, target_ip: str = Form(...)):
    """Faz ping ou verifica conectividade do IP introduzido pelo utilizador."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    
    # Se o utilizador inseriu um IP específico
    command = ["ping", param, "2", target_ip]
    
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=5)
        if process.returncode == 0:
            output = f"[ONLINE] O dispositivo {target_ip} respondeu com sucesso!\n\nDetalhes:\n{process.stdout}"
        else:
            output = f"[OFFLINE / ANOMALIA] O dispositivo {target_ip} não está a responder ou está inacessível.\n\nDetalhes:\n{process.stderr or process.stdout}"
    except Exception as e:
        output = f"Erro ao executar verificação: {str(e)}"

    return templates.TemplateResponse(
      request=request,
      name="index.html",
      context={
          "request": request,
          "result": output,
          "target_ip": target_ip,
      },
    )