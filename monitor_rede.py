#!/usr/bin/env python3
"""
Script simples de monitoramento de rede em Python:
- Testa disponibilidade e latência via ICMP ping
- Testa abertura de portas TCP
- Salva histórico em arquivo CSV
"""

import csv
import platform
import re
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path

# ==============================================================================
# CONFIGURAÇÕES DO MONITORAMENTO
# ==============================================================================
INTERVALO_SEGUNDOS = 10  # Tempo entre ciclos no modo contínuo
TIMEOUT_TCP = 2.0        # Timeout em segundos para teste de porta TCP
ARQUIVO_LOG = Path("historico_rede.csv")

# Alvos para monitorar:
# "portas": lista de portas TCP para testar (pode deixar vazia [] para só pingar)
ALVOS = [
    {"nome": "Gateway / Roteador", "host": "192.168.1.1", "portas": [80, 443]},
    {"nome": "Cloudflare DNS", "host": "1.1.1.1", "portas": [53]},
    {"nome": "Google DNS", "host": "8.8.8.8", "portas": [53]},
    {"nome": "GitHub", "host": "github.com", "portas": [443]},
]


# ==============================================================================
# FUNÇÕES DE MONITORAMENTO
# ==============================================================================
def ping_host(host: str, timeout: int = 2) -> tuple[bool, float | None]:
    """
    Executa ping no host e retorna (online, latencia_ms).
    Funciona em Linux/macOS e Windows.
    """
    sistema = platform.system().lower()

    if sistema == "windows":
        comando = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        comando = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        if resultado.returncode != 0:
            return False, None

        saida = resultado.stdout
        # Extrai tempo em ms (ex.: "time=14.2 ms" ou "tempo=14ms" / "time<1ms")
        match = re.search(r"(?:time|tempo)[<=]\s*(\d+(?:[.,]\d+)?)\s*ms", saida, re.IGNORECASE)
        if match:
            latencia = float(match.group(1).replace(",", "."))
            return True, latencia

        return True, None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, None


def checar_porta_tcp(host: str, porta: int, timeout: float = 2.0) -> tuple[bool, float | None]:
    """
    Tenta abrir uma conexão TCP na porta informada e mede o tempo em ms.
    """
    inicio = time.perf_counter()
    try:
        with socket.create_connection((host, porta), timeout=timeout):
            decorrido_ms = (time.perf_counter() - inicio) * 1000
            return True, round(decorrido_ms, 2)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None


def preparar_csv(caminho: Path) -> None:
    """Cria o arquivo CSV com cabeçalho se ainda não existir."""
    if not caminho.exists():
        with caminho.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "nome_alvo",
                "host",
                "tipo_teste",
                "porta",
                "status",
                "latencia_ms",
            ])


def registrar_csv(
    caminho: Path,
    timestamp: str,
    nome: str,
    host: str,
    tipo_teste: str,
    porta: int | str,
    status: str,
    latencia_ms: float | None,
) -> None:
    """Adiciona uma linha ao arquivo CSV de log."""
    with caminho.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            nome,
            host,
            tipo_teste,
            porta,
            status,
            latencia_ms if latencia_ms is not None else "",
        ])


def executar_ciclo() -> None:
    """Executa uma rodada completa de testes em todos os alvos."""
    preparar_csv(ARQUIVO_LOG)
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[{agora}] Iniciando verificação de rede...")
    print("-" * 72)

    for alvo in ALVOS:
        nome = alvo["nome"]
        host = alvo["host"]
        portas = alvo.get("portas", [])

        # 1. Teste de Ping
        online, latencia = ping_host(host)
        status_ping = "ONLINE" if online else "OFFLINE"
        lat_texto = f"{latencia:.1f} ms" if latencia is not None else "N/A"
        icone = "OK" if online else "FALHA"

        print(f"[{icone:5}] {nome} ({host}) -> PING: {status_ping} ({lat_texto})")
        registrar_csv(
            ARQUIVO_LOG, agora, nome, host, "PING", "-", status_ping, latencia
        )

        # 2. Teste de Portas TCP
        for porta in portas:
            aberta, lat_tcp = checar_porta_tcp(host, porta, timeout=TIMEOUT_TCP)
            status_tcp = "ABERTA" if aberta else "FECHADA"
            lat_tcp_texto = f"{lat_tcp:.1f} ms" if lat_tcp is not None else "N/A"
            icone_tcp = "OK" if aberta else "FALHA"

            print(
                f"       [{icone_tcp:5}] Porta TCP {porta}: {status_tcp} ({lat_tcp_texto})"
            )
            registrar_csv(
                ARQUIVO_LOG, agora, nome, host, "TCP", porta, status_tcp, lat_tcp
            )


def main() -> None:
    print("Monitor de Rede iniciado. Pressione Ctrl+C para encerrar.")
    try:
        while True:
            executar_ciclo()
            time.sleep(INTERVALO_SEGUNDOS)
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.")
        print(f"Logs salvos em: {ARQUIVO_LOG.resolve()}")


if __name__ == "__main__":
    main()
