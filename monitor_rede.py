#!/usr/bin/env python3
"""
Monitor de Rede em Python (v2)
- Verifica ping/latência e portas TCP em paralelo
- Salva histórico em CSV
- Detecta mudança de estado (queda/recuperação) com cooldown anti-spam
- Suporta webhook (Discord, Slack, etc.) e execução única (--once)
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib import error, request

CONFIG_PADRAO: dict[str, Any] = {
    "intervalo_segundos": 10,
    "timeout_tcp": 2.0,
    "timeout_ping": 2,
    "max_workers": 8,
    "cooldown_alerta_segundos": 300,
    "arquivo_log": "historico_rede.csv",
    "webhook_url": "",
    "alvos": [
        {"nome": "Gateway / Roteador", "host": "192.168.1.1", "portas": [80, 443]},
        {"nome": "Cloudflare DNS", "host": "1.1.1.1", "portas": [53]},
        {"nome": "Google DNS", "host": "8.8.8.8", "portas": [53]},
        {"nome": "GitHub", "host": "github.com", "portas": [443]},
    ],
}


def carregar_config(caminho: Path) -> dict[str, Any]:
    """Carrega config.json ou cria um arquivo padrão se não existir."""
    if not caminho.exists():
        caminho.write_text(
            json.dumps(CONFIG_PADRAO, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return json.loads(json.dumps(CONFIG_PADRAO))

    dados = json.loads(caminho.read_text(encoding="utf-8"))
    config = json.loads(json.dumps(CONFIG_PADRAO))
    config.update({k: v for k, v in dados.items() if v is not None})
    if "alvos" in dados and isinstance(dados["alvos"], list):
        config["alvos"] = dados["alvos"]
    return config


def ping_host(host: str, timeout: int = 2) -> tuple[bool, float | None]:
    """Executa ping no host e retorna (online, latencia_ms)."""
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

        match = re.search(
            r"(?:time|tempo)[<=]\s*(\d+(?:[.,]\d+)?)\s*ms",
            resultado.stdout,
            re.IGNORECASE,
        )
        if match:
            return True, float(match.group(1).replace(",", "."))
        return True, None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, None


def checar_porta_tcp(
    host: str, porta: int, timeout: float = 2.0
) -> tuple[bool, float | None]:
    """Testa conexão TCP em uma porta e retorna (aberta, latencia_ms)."""
    inicio = time.perf_counter()
    try:
        with socket.create_connection((host, porta), timeout=timeout):
            decorrido_ms = (time.perf_counter() - inicio) * 1000
            return True, round(decorrido_ms, 2)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None


def avaliar_alvo(
    alvo: dict[str, Any], timeout_ping: int, timeout_tcp: float
) -> dict[str, Any]:
    """Executa os testes de ping e portas TCP de um único alvo."""
    nome = str(alvo["nome"])
    host = str(alvo["host"])
    portas = [int(p) for p in alvo.get("portas", [])]

    online, lat_ping = ping_host(host, timeout=timeout_ping)
    resultados_portas: list[dict[str, Any]] = []

    for porta in portas:
        aberta, lat_tcp = checar_porta_tcp(host, porta, timeout=timeout_tcp)
        resultados_portas.append(
            {
                "porta": porta,
                "aberta": aberta,
                "status": "ABERTA" if aberta else "FECHADA",
                "latencia_ms": lat_tcp,
            }
        )

    todas_portas_ok = all(p["aberta"] for p in resultados_portas)
    saude_geral = "OK" if (online and todas_portas_ok) else "FALHA"

    return {
        "nome": nome,
        "host": host,
        "online": online,
        "status_ping": "ONLINE" if online else "OFFLINE",
        "latencia_ping_ms": lat_ping,
        "portas": resultados_portas,
        "saude_geral": saude_geral,
    }


def preparar_csv(caminho: Path) -> None:
    """Cria o CSV com cabeçalho se ainda não existir."""
    if not caminho.exists():
        with caminho.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "timestamp",
                    "nome_alvo",
                    "host",
                    "tipo_teste",
                    "porta",
                    "status",
                    "latencia_ms",
                ]
            )


def registrar_resultados_csv(
    caminho: Path, timestamp: str, resultados: list[dict[str, Any]]
) -> None:
    """Grava os resultados de um ciclo no CSV."""
    preparar_csv(caminho)
    with caminho.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for item in resultados:
            writer.writerow(
                [
                    timestamp,
                    item["nome"],
                    item["host"],
                    "PING",
                    "-",
                    item["status_ping"],
                    item["latencia_ping_ms"] if item["latencia_ping_ms"] is not None else "",
                ]
            )
            for p in item["portas"]:
                writer.writerow(
                    [
                        timestamp,
                        item["nome"],
                        item["host"],
                        "TCP",
                        p["porta"],
                        p["status"],
                        p["latencia_ms"] if p["latencia_ms"] is not None else "",
                    ]
                )


def enviar_webhook(webhook_url: str, mensagem: str) -> None:
    """Envia alerta JSON compatível com Discord/Slack/webhooks genéricos."""
    if not webhook_url:
        return

    payload = json.dumps({"content": mensagem, "text": mensagem}).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=5):
            pass
    except (error.URLError, TimeoutError, OSError) as exc:
        print(f"  [AVISO] Falha ao enviar webhook: {exc}")


def processar_alertas(
    resultados: list[dict[str, Any]],
    estado_anterior: dict[str, str],
    ultimo_alerta: dict[str, float],
    cooldown: int,
    webhook_url: str,
    agora_str: str,
) -> None:
    """Dispara alerta quando há mudança de estado respeitando cooldown."""
    agora_ts = time.time()

    for item in resultados:
        chave = f"{item['nome']}|{item['host']}"
        estado_atual = item["saude_geral"]
        anterior = estado_anterior.get(chave)

        if anterior is None:
            estado_anterior[chave] = estado_atual
            if estado_atual == "FALHA":
                msg = (
                    f"[ALERTA REDE] {agora_str} - {item['nome']} ({item['host']}) "
                    f"iniciou em FALHA (PING={item['status_ping']})."
                )
                print(f"  >>> {msg}")
                enviar_webhook(webhook_url, msg)
                ultimo_alerta[chave] = agora_ts
            continue

        if estado_atual != anterior:
            passou_cooldown = (agora_ts - ultimo_alerta.get(chave, 0.0)) >= cooldown
            estado_anterior[chave] = estado_atual

            if passou_cooldown:
                if estado_atual == "FALHA":
                    portas_fechadas = [
                        str(p["porta"]) for p in item["portas"] if not p["aberta"]
                    ]
                    detalhe_portas = (
                        f" | Portas fechadas: {', '.join(portas_fechadas)}"
                        if portas_fechadas
                        else ""
                    )
                    msg = (
                        f"[QUEDA] {agora_str} - {item['nome']} ({item['host']}) "
                        f"ficou em FALHA (PING={item['status_ping']}{detalhe_portas})."
                    )
                else:
                    lat = (
                        f"{item['latencia_ping_ms']:.1f}ms"
                        if item["latencia_ping_ms"] is not None
                        else "N/A"
                    )
                    msg = (
                        f"[RECUPERADO] {agora_str} - {item['nome']} ({item['host']}) "
                        f"voltou ao normal (PING={item['status_ping']}, lat={lat})."
                    )

                print(f"  >>> {msg}")
                enviar_webhook(webhook_url, msg)
                ultimo_alerta[chave] = agora_ts


def imprimir_resumo(agora_str: str, resultados: list[dict[str, Any]]) -> None:
    """Exibe um resumo formatado no terminal."""
    total_ok = sum(1 for r in resultados if r["saude_geral"] == "OK")
    print(f"\n[{agora_str}] Resumo: {total_ok}/{len(resultados)} alvos saudáveis")
    print("-" * 78)

    for r in resultados:
        lat_txt = (
            f"{r['latencia_ping_ms']:.1f} ms"
            if r["latencia_ping_ms"] is not None
            else "N/A"
        )
        portas_txt = (
            ", ".join(
                f"{p['porta']}:{'OK' if p['aberta'] else 'FAIL'}" for p in r["portas"]
            )
            if r["portas"]
            else "sem portas"
        )
        print(
            f"[{r['saude_geral']:5}] {r['nome']:<20} ({r['host']:<15}) | "
            f"PING {r['status_ping']:<7} ({lat_txt:<8}) | TCP [{portas_txt}]"
        )


def executar_ciclo(
    config: dict[str, Any],
    estado_anterior: dict[str, str],
    ultimo_alerta: dict[str, float],
) -> None:
    """Executa uma rodada completa de testes em paralelo."""
    alvos = config.get("alvos", [])
    timeout_ping = int(config.get("timeout_ping", 2))
    timeout_tcp = float(config.get("timeout_tcp", 2.0))
    max_workers = max(1, int(config.get("max_workers", 8)))
    cooldown = int(config.get("cooldown_alerta_segundos", 300))
    webhook_url = str(config.get("webhook_url", "")).strip()
    arquivo_log = Path(str(config.get("arquivo_log", "historico_rede.csv")))

    agora_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    resultados: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futuros = {
            pool.submit(avaliar_alvo, alvo, timeout_ping, timeout_tcp): idx
            for idx, alvo in enumerate(alvos)
        }
        ordenados: dict[int, dict[str, Any]] = {}
        for futuro in as_completed(futuros):
            idx = futuros[futuro]
            ordenados[idx] = futuro.result()
        resultados = [ordenados[i] for i in sorted(ordenados)]

    imprimir_resumo(agora_str, resultados)
    registrar_resultados_csv(arquivo_log, agora_str, resultados)
    processar_alertas(
        resultados=resultados,
        estado_anterior=estado_anterior,
        ultimo_alerta=ultimo_alerta,
        cooldown=cooldown,
        webhook_url=webhook_url,
        agora_str=agora_str,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor de rede em Python")
    parser.add_argument(
        "-c",
        "--config",
        default="config.json",
        help="Caminho para o arquivo de configuração JSON (padrão: config.json)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Executa apenas um ciclo e encerra (ideal para cron)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = Path(args.config)
    config = carregar_config(config_path)

    estado_anterior: dict[str, str] = {}
    ultimo_alerta: dict[str, float] = {}
    intervalo = max(1, int(config.get("intervalo_segundos", 10)))

    print(f"Monitor de Rede iniciado usando '{config_path}'. Ctrl+C para sair.")
    try:
        while True:
            executar_ciclo(config, estado_anterior, ultimo_alerta)
            if args.once:
                break
            time.sleep(intervalo)
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado.")


if __name__ == "__main__":
    main()
