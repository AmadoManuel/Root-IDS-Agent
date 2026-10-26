
import json
import logging
import platform
import socket
import time

from datetime import datetime, timezone
from pathlib import Path

import psutil


# Configuração inicial do RootIDS Agent
INTERVAL_SECONDS = 10

CPU_THRESHOLD = 85.0
RAM_THRESHOLD = 90.0
DISK_THRESHOLD = 90.0

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "agent.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8",
)


def collect_metrics():
    """Recolhe métricas básicas do computador local."""

    memory = psutil.virtual_memory()

    disk_path = Path.home().anchor
    disk = psutil.disk_usage(disk_path)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": memory.percent,
        "memory_available_mb": round(
            memory.available / (1024 ** 2), 2
        ),
        "disk_percent": disk.percent,
        "disk_free_gb": round(
            disk.free / (1024 ** 3), 2
        ),
    }


def detect_anomalies(metrics):
    """Identifica valores acima dos limites configurados."""

    anomalies = []

    if metrics["cpu_percent"] >= CPU_THRESHOLD:
        anomalies.append({
            "metric": "cpu_percent",
            "value": metrics["cpu_percent"],
            "threshold": CPU_THRESHOLD,
            "severity": "warning",
        })

    if metrics["memory_percent"] >= RAM_THRESHOLD:
        anomalies.append({
            "metric": "memory_percent",
            "value": metrics["memory_percent"],
            "threshold": RAM_THRESHOLD,
            "severity": "warning",
        })

    if metrics["disk_percent"] >= DISK_THRESHOLD:
        anomalies.append({
            "metric": "disk_percent",
            "value": metrics["disk_percent"],
            "threshold": DISK_THRESHOLD,
            "severity": "warning",
        })

    return anomalies


def monitor():
    """Executa o ciclo contínuo de monitorização."""

    print("=" * 55)
    print("RootIDS Agent - Monitorização local")
    print(f"Computador: {socket.gethostname()}")
    print(f"Intervalo: {INTERVAL_SECONDS} segundos")
    print("Pressiona Ctrl+C para terminar.")
    print("=" * 55)

    while True:
        try:
            metrics = collect_metrics()
            anomalies = detect_anomalies(metrics)

            event = {
                "type": "system_metrics",
                "metrics": metrics,
                "anomalies": anomalies,
            }

            print(json.dumps(event, indent=2, ensure_ascii=False))

            logging.info(
                json.dumps(event, ensure_ascii=False)
            )

            if anomalies:
                print("\n[ALERTA] Foram identificadas anomalias:")

                for anomaly in anomalies:
                    print(
                        f"- {anomaly['metric']}: "
                        f"{anomaly['value']}% "
                        f"(limite: {anomaly['threshold']}%)"
                    )

                logging.warning(
                    json.dumps(
                        {
                            "type": "anomaly_detected",
                            "hostname": metrics["hostname"],
                            "anomalies": anomalies,
                        },
                        ensure_ascii=False,
                    )
                )

            time.sleep(INTERVAL_SECONDS)

        except KeyboardInterrupt:
            print("\nRootIDS Agent terminado pelo utilizador.")
            break

        except Exception:
            logging.exception(
                "Erro durante o ciclo de monitorização."
            )
            print(
                "Ocorreu um erro. Consulta logs/agent.log."
            )
            time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    monitor()
