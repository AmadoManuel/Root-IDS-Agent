
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import platform
import subprocess
import os

app = FastAPI(title="RootIDS - Sistema de Deteção de Intrusão", version="1.1")

os.makedirs("templates", exist_ok=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RootIDS - Scanner IPv4</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #101820;
            color: #f2f5f7;
            margin: 0;
            padding: 25px;
        }
        .container {
            max-width: 900px;
            margin: auto;
            background: #1c2833;
            padding: 25px;
            border-radius: 10px;
        }
        h1 { color: #55c2ff; text-align: center; }
        p { color: #c9d3dc; }
        form { display: flex; gap: 10px; margin: 25px 0; }
        input {
            flex: 1;
            min-width: 0;
            padding: 12px;
            border-radius: 5px;
            border: 1px solid #526575;
            font-size: 16px;
        }
        button {
            padding: 12px 18px;
            border: 0;
            border-radius: 5px;
            background: #007bff;
            color: white;
            cursor: pointer;
        }
        button:hover { background: #0056b3; }
        .results {
            background: #0b1117;
            padding: 18px;
            border-radius: 5px;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            font-family: Consolas, monospace;
            line-height: 1.6;
        }
        .note { font-size: 13px; }
        @media (max-width: 600px) {
            form { flex-direction: column; }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>RootIDS</h1>
    <h2>Scanner e Classificador IPv4</h2>

    <p>
        Introduza um endereço IPv4 ou uma sub-rede CIDR.
        Exemplo: 192.168.1.10 ou 192.168.1.0/24.
    </p>

    <form method="post" action="/scan">
        <input
            type="text"
            name="target_ip"
            placeholder="IP ou sub-rede CIDR"
            value="{{ target_ip }}"
            required
        >
        <button type="submit">Iniciar análise</button>
    </form>

    {% if result %}
        <h3>Relatório da análise</h3>
        <div class="results">{{ result }}</div>
    {% endif %}

    <p class="note">
        Utilize apenas em redes próprias ou para as quais tenha autorização.
        A ausência de resposta ao ping não prova que um dispositivo esteja offline.
    </p>
</div>
</body>
</html>
"""

with open("templates/index.html", "w", encoding="utf-8") as f:
    f.write(HTML_TEMPLATE)

templates = Jinja2Templates(directory="templates")


def classificar_ipv4(ip):
    """Identifica a classe histórica do endereço IPv4."""
    primeiro_octeto = int(str(ip).split(".")[0])

    if primeiro_octeto == 0:
        return "Especial (0/8)"
    if 1 <= primeiro_octeto <= 126:
        return "A"
    if primeiro_octeto == 127:
        return "Loopback (127/8)"
    if 128 <= primeiro_octeto <= 191:
        return "B"
    if 192 <= primeiro_octeto <= 223:
        return "C"
    if 224 <= primeiro_octeto <= 239:
        return "D - Multicast"
    return "E - Reservada/experimental"


def verificar_ip(ip):
    """Verifica a resposta ao ping de um único IPv4."""
    sistema = platform.system().lower()

    if sistema == "windows":
        comando = ["ping", "-n", "1", "-w", "700", str(ip)]
        timeout = 2
    else:
        comando = ["ping", "-c", "1", "-W", "1", str(ip)]
        timeout = 3

    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace"
        )

        if resultado.returncode == 0:
            return f"[ATIVO] {ip}"
        return f"[SEM RESPOSTA] {ip}"

    except subprocess.TimeoutExpired:
        return f"[TEMPO ESGOTADO] {ip}"
    except OSError as erro:
        return f"[ERRO] {ip}: {erro}"


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "result": None,
            "target_ip": ""
        }
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan_target(
    request: Request,
    target_ip: str = Form(...)
):
    entrada = target_ip.strip()
    linhas = []

    try:
        if "/" in entrada:
            rede = ipaddress.ip_network(entrada, strict=False)
            if rede.version != 4:
                raise ValueError("Apenas endereços IPv4 são suportados.")
            ips = list(rede.hosts())
            endereco_individual = False
        else:
            endereco = ipaddress.ip_address(entrada)
            if endereco.version != 4:
                raise ValueError("Apenas endereços IPv4 são suportados.")
            rede = ipaddress.ip_network(f"{endereco}/32")
            ips = [endereco]
            endereco_individual = True

    except ValueError as erro:
        linhas.append(f"[ENTRADA INVÁLIDA] {erro}")
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "result": "\n".join(linhas),
                "target_ip": entrada
            }
        )

    linhas.append("=== INFORMAÇÕES DA REDE ===")
    linhas.append(f"Entrada: {entrada}")
    linhas.append(f"Rede: {rede}")
    linhas.append(f"Endereços na rede: {rede.num_addresses}")

    if not endereco_individual and rede.num_addresses > 256:
        linhas.append(
            "\n[ANÁLISE INTERROMPIDA] A rede excede o limite "
            "de 256 endereços por análise. Divida-a em sub-redes "
            "menores e autorizadas."
        )
    else:
        linhas.append("\n=== CLASSIFICAÇÃO IPv4 ===")

        for ip in ips:
            linhas.append(f"{ip} -> Classe {classificar_ipv4(ip)}")

        if any(
            classificar_ipv4(ip).startswith(("D", "E", "Especial", "Loopback"))
            for ip in ips
        ):
            linhas.append(
                "\nAviso: endereços multicast, reservados e loopback "
                "não são alvos normais de descoberta de computadores."
            )

        alvos = [
            ip for ip in ips
            if ip.is_global is False
            and not ip.is_loopback
            and not ip.is_multicast
            and not ip.is_unspecified
            and not ip.is_reserved
        ]

        # Para um IP individual, também permite testar um endereço
        # público, desde que exista autorização para o testar.
        if endereco_individual:
            alvos = [
                ip for ip in ips
                if not ip.is_loopback
                and not ip.is_multicast
                and not ip.is_unspecified
                and not ip.is_reserved
            ]

        if not alvos:
            linhas.append(
                "\nNenhum alvo elegível para verificação por ping."
            )
        else:
            linhas.append("\n=== VERIFICAÇÃO DE CONECTIVIDADE ===")
            linhas.append(
                "A verificar os endereços elegíveis; "
                "a ausência de resposta não confirma que estejam offline."
            )

            with ThreadPoolExecutor(max_workers=32) as executor:
                resultados = executor.map(verificar_ip, alvos)
                linhas.extend(resultados)

        linhas.append("\n=== FIM DA ANÁLISE ===")

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "result": "\n".join(linhas),
            "target_ip": entrada
        }
    )
