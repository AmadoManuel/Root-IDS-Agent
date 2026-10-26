import ipaddress
import json
import logging
import platform
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path

# Configuração de Logs e Diretórios
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "agent_desktop.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8",
)

# Intervalo de verificação da rede em segundos
SCAN_INTERVAL_SECONDS = 30

def get_local_network_prefix():
    """Tenta descobrir o prefixo de rede local do computador (ex: 192.168.1.)."""
    try:
        # Obtém o hostname e o IP local
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        # Extrai os primeiros 3 octetos (assumindo máscara /24 comum em redes domésticas/escritório)
        parts = local_ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}."
    except Exception as e:
        logging.error(f"Erro ao obter IP local: {e}")
    return "192.168.1."  # Fallback padrão

def ping_device(ip):
    """Envia um ping rápido para verificar se o dispositivo está ativo na rede."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "500", ip] # timeout de 500ms
    
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def scan_network_devices(network_prefix):
    """Varre os IPs comuns da rede local para detetar dispositivos ativos."""
    active_devices = []
    print(f"[{datetime.now()}] A iniciar varrimento da rede ({network_prefix}1 a {network_prefix}254)...")
    
    # Para testes rápidos e eficientes, varremos uma sub-rede /24 típica
    # Nota: Em redes grandes, no futuro usaremos threads, mas para começar de forma estável fazemos sequencial ou reduzida.
    # Vamos varrer IPs comuns de 1 a 50 para teste rápido, ou pode expandir até 254
    for i in range(1, 51):
        ip = f"{network_prefix}{i}"
        if ping_device(ip):
            active_devices.append(ip)
            
    return active_devices

def run_desktop_agent():
    """Executa o ciclo principal do agente de ambiente de trabalho focado em rede."""
    print(f"[{datetime.now()}] RootIDS Agent_desktop iniciado.")
    logging.info("RootIDS Agent_desktop iniciado com sucesso.")
    
    network_prefix = get_local_network_prefix()
    print(f"🌐 Prefixo de rede identificado para monitorização: {network_prefix}*")
    
    previous_devices = set()

    try:
        while True:
            current_devices = set(scan_network_devices(network_prefix))
            
            print(f"[{datetime.now()}] Dispositivos ativos detetados na rede: {len(current_devices)} -> {list(current_devices)}")
            logging.info(f"Dispositivos ativos detetados: {list(current_devices)}")
            
            if previous_devices:
                new_devices = current_devices - previous_devices
                offline_devices = previous_devices - current_devices
                
                if new_devices:
                    msg = f"NOVO DISPOSITIVO NA REDE: {list(new_devices)}"
                    print(f"🟢 {msg}")
                    logging.info(msg)
                    
                if offline_devices:
                    msg = f"DISPOSITIVO DESAPARECEU DA REDE (Possível falha ou remoção): {list(offline_devices)}"
                    print(f"🚨 {msg}")
                    logging.warning(msg)
            
            previous_devices = current_devices
            
            print(f"A aguardar {SCAN_INTERVAL_SECONDS} segundos para o próximo ciclo de rede...\n")
            time.sleep(SCAN_INTERVAL_SECONDS)
            
    except KeyboardInterrupt:
        print(f"\n[{datetime.now()}] Agent_desktop interrompido pelo utilizador.")
        logging.info("Agent_desktop parado pelo utilizador.")

if __name__ == "__main__":
    run_desktop_agent()