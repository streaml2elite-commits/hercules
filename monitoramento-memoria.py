#!/usr/bin/env python3
"""
Monitor de Memória RAM e Swap em Python (Linux)
- Lê /proc/meminfo (RAM total, disponível, usada, cache/buffers e Swap)
- Lista os processos que mais consomem RAM quando o limite é atingido
- Salva histórico em CSV
- Dispara alertas com cooldown (console / webhook) e suporta --once
"""

from __future__ import annotations

import argparse
import csv
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib import error, request

CONFIG_MEMORIA_PADRAO: dict[str, Any] = {
    "intervalo_segundos": 10,
    "alerta_ram_percentual": 85.0,
    "alerta_swap_percentual": 50.0,
    "top_processos": 5,
    "cooldown_alerta_segundos": 300,
    "arquivo_log": "historico_memoria.csv",
    "webhook_url": "",
}


def carregar_config(caminho: Path) -> dict[str, Any]:
    """Carrega config_memoria.json ou cria um arquivo padrão se não existir."""
    if not caminho.exists():
        caminho.write_text(
            json.dumps(CONFIG_MEMORIA_PADRAO, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return json.loads(json.dumps(CONFIG_MEMORIA_PADRAO))

    dados = json.loads(caminho.read_text(encoding="utf-8"))
    config = json.loads(json.dumps(CONFIG_MEMORIA_PADRAO))
    config.update({k: v for k, v in dados.items() if v is not None})
    return config


def ler_meminfo() -> dict[str, int]:
    """Lê /proc/meminfo e retorna valores em KiB."""
    valores: dict[str, int] = {}
    meminfo_path = Path("/proc/meminfo")
    if not meminfo_path.exists():
        raise RuntimeError("/proc/meminfo não encontrado. Este script é voltado ao Linux.")

    for linha in meminfo_path.read_text(encoding="utf-8").splitlines():
        partes = linha.split(":")
        if len(partes) != 2:
            continue
        chave = partes[0].strip()
        numero = partes[1].strip().split()[0]
        if numero.isdigit():
            valores[chave] = int(numero)

    return valores


def kib_para_mib(kib: int) -> float:
    return round(kib / 1024, 2)


def coletar_metricas_memoria() -> dict[str, Any]:
    """Calcula métricas de RAM e Swap a partir de /proc/meminfo."""
    info = ler_meminfo()

    mem_total_kib = info.get("MemTotal", 0)
    mem_available_kib = info.get("MemAvailable", info.get("MemFree", 0))
    mem_usada_kib = max(0, mem_total_kib - mem_available_kib)
    buffers_cache_kib = info.get("Buffers", 0) + info.get("Cached", 0)

    swap_total_kib = info.get("SwapTotal", 0)
    swap_free_kib = info.get("SwapFree", 0)
    swap_usada_kib = max(0, swap_total_kib - swap_free_kib)

    ram_pct = (mem_usada_kib / mem_total_kib * 100) if mem_total_kib > 0 else 0.0
    swap_pct = (swap_usada_kib / swap_total_kib * 100) if swap_total_kib > 0 else 0.0

    return {
        "ram_total_mib": kib_para_mib(mem_total_kib),
        "ram_usada_mib": kib_para_mib(mem_usada_kib),
        "ram_disponivel_mib": kib_para_mib(mem_available_kib),
        "buffers_cache_mib": kib_para_mib(buffers_cache_kib),
        "ram_pct": round(ram_pct, 2),
        "swap_total_mib": kib_para_mib(swap_total_kib),
        "swap_usada_mib": kib_para_mib(swap_usada_kib),
        "swap_pct": round(swap_pct, 2),
    }


def top_processos_memoria(limite: int = 5) -> list[dict[str, Any]]:
    """Lista os processos com maior RSS (memória residente em MiB)."""
    if limite <= 0:
        return []

    processos: list[dict[str, Any]] = []
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.is_dir() or not proc_dir.name.isdigit():
            continue

        pid = int(proc_dir.name)
        status_file = proc_dir / "status"
        try:
            conteudo = status_file.read_text(encoding="utf-8", errors="ignore")
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            continue

        nome = ""
        rss_kib = 0
        for linha in conteudo.splitlines():
            if linha.startswith("Name:"):
                nome = linha.split(":", 1)[1].strip()
            elif linha.startswith("VmRSS:"):
                partes = linha.split(":", 1)[1].strip().split()
                if partes and partes[0].isdigit():
                    rss_kib = int(partes[0])
                    break

        if rss_kib > 0:
            processos.append(
                {
                    "pid": pid,
                    "nome": nome or "desconhecido",
                    "rss_mib": kib_para_mib(rss_kib),
                }
            )

    processos.sort(key=lambda p: p["rss_mib"], reverse=True)
    return processos[:limite]


def preparar_csv(caminho: Path) -> None:
    """Cria o CSV com cabeçalho se ainda não existir."""
    if not caminho.exists():
        with caminho.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "timestamp",
                    "ram_usada_mib",
                    "ram_disponivel_mib",
                    "ram_total_mib",
                    "buffers_cache_mib",
                    "ram_pct",
                    "swap_usada_mib",
                    "swap_total_mib",
                    "swap_pct",
                    "status",
                ]
            )


def registrar_csv(
    caminho: Path, timestamp: str, metricas: dict[str, Any], status: str
) -> None:
    """Adiciona uma linha ao arquivo CSV de histórico."""
    preparar_csv(caminho)
    with caminho.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                timestamp,
                metricas["ram_usada_mib"],
                metricas["ram_disponivel_mib"],
                metricas["ram_total_mib"],
                metricas["buffers_cache_mib"],
                metricas["ram_pct"],
                metricas["swap_usada_mib"],
                metricas["swap_total_mib"],
                metricas["swap_pct"],
                status,
            ]
        )


def enviar_webhook(webhook_url: str, mensagem: str) -> None:
    """Envia mensagem JSON para webhook (Discord, Slack, etc.)."""
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


def imprimir_resumo(
    agora_str: str,
    metricas: dict[str, Any],
    status: str,
    procs: list[dict[str, Any]],
) -> None:
    """Exibe métricas de memória no terminal."""
    print(f"\n[{agora_str}] Memória [{status}]")
    print("-" * 74)
    print(
        f"RAM : {metricas['ram_usada_mib']:8.1f} / {metricas['ram_total_mib']:8.1f} MiB "
        f"({metricas['ram_pct']:5.1f}%) | Disp: {metricas['ram_disponivel_mib']:8.1f} MiB | "
        f"Cache/Buf: {metricas['buffers_cache_mib']:8.1f} MiB"
    )
    print(
        f"SWAP: {metricas['swap_usada_mib']:8.1f} / {metricas['swap_total_mib']:8.1f} MiB "
        f"({metricas['swap_pct']:5.1f}%)"
    )

    if procs:
        resumo_procs = ", ".join(
            f"{p['nome']}(pid={p['pid']}: {p['rss_mib']:.1f}MiB)" for p in procs
        )
        print(f"Top RAM: {resumo_procs}")


def processar_alerta(
    metricas: dict[str, Any],
    status_atual: str,
    estado_anterior: dict[str, str],
    ultimo_alerta: dict[str, float],
    cooldown: int,
    webhook_url: str,
    agora_str: str,
    procs: list[dict[str, Any]],
) -> None:
    """Dispara alerta quando o status muda para ALERTA ou volta para NORMAL."""
    chave = "memoria_sistema"
    anterior = estado_anterior.get(chave)
    agora_ts = time.time()

    if anterior is None:
        estado_anterior[chave] = status_atual
        if status_atual == "ALERTA":
            top_txt = (
                " | Top: " + ", ".join(f"{p['nome']}({p['rss_mib']}MiB)" for p in procs)
                if procs
                else ""
            )
            msg = (
                f"[ALERTA MEMÓRIA] {agora_str} - RAM {metricas['ram_pct']}% "
                f"({metricas['ram_usada_mib']}/{metricas['ram_total_mib']} MiB), "
                f"SWAP {metricas['swap_pct']}%{top_txt}"
            )
            print(f"  >>> {msg}")
            enviar_webhook(webhook_url, msg)
            ultimo_alerta[chave] = agora_ts
        return

    if status_atual != anterior:
        passou_cooldown = (agora_ts - ultimo_alerta.get(chave, 0.0)) >= cooldown
        estado_anterior[chave] = status_atual

        if passou_cooldown:
            if status_atual == "ALERTA":
                top_txt = (
                    " | Top: "
                    + ", ".join(f"{p['nome']}({p['rss_mib']}MiB)" for p in procs)
                    if procs
                    else ""
                )
                msg = (
                    f"[CRÍTICO MEMÓRIA] {agora_str} - RAM {metricas['ram_pct']}% "
                    f"({metricas['ram_usada_mib']}/{metricas['ram_total_mib']} MiB), "
                    f"SWAP {metricas['swap_pct']}%{top_txt}"
                )
            else:
                msg = (
                    f"[NORMALIZADO MEMÓRIA] {agora_str} - RAM {metricas['ram_pct']}% "
                    f"({metricas['ram_disponivel_mib']} MiB livres), "
                    f"SWAP {metricas['swap_pct']}%"
                )

            print(f"  >>> {msg}")
            enviar_webhook(webhook_url, msg)
            ultimo_alerta[chave] = agora_ts


def executar_ciclo(
    config: dict[str, Any],
    estado_anterior: dict[str, str],
    ultimo_alerta: dict[str, float],
) -> None:
    """Executa uma rodada de leitura e registro de memória."""
    limite_ram = float(config.get("alerta_ram_percentual", 85.0))
    limite_swap = float(config.get("alerta_swap_percentual", 50.0))
    top_n = int(config.get("top_processos", 5))
    cooldown = int(config.get("cooldown_alerta_segundos", 300))
    webhook_url = str(config.get("webhook_url", "")).strip()
    arquivo_log = Path(str(config.get("arquivo_log", "historico_memoria.csv")))

    agora_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    metricas = coletar_metricas_memoria()

    excedeu_ram = metricas["ram_pct"] >= limite_ram
    excedeu_swap = (
        metricas["swap_total_mib"] > 0 and metricas["swap_pct"] >= limite_swap
    )
    status = "ALERTA" if (excedeu_ram or excedeu_swap) else "NORMAL"

    procs = top_processos_memoria(top_n) if status == "ALERTA" else []

    imprimir_resumo(agora_str, metricas, status, procs)
    registrar_csv(arquivo_log, agora_str, metricas, status)
    processar_alerta(
        metricas=metricas,
        status_atual=status,
        estado_anterior=estado_anterior,
        ultimo_alerta=ultimo_alerta,
        cooldown=cooldown,
        webhook_url=webhook_url,
        agora_str=agora_str,
        procs=procs,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor de memória RAM e Swap em Python")
    parser.add_argument(
        "-c",
        "--config",
        default="config_memoria.json",
        help="Arquivo de configuração JSON (padrão: config_memoria.json)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Executa apenas uma leitura e encerra",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = Path(args.config)
    config = carregar_config(config_path)

    estado_anterior: dict[str, str] = {}
    ultimo_alerta: dict[str, float] = {}
    intervalo = max(1, int(config.get("intervalo_segundos", 10)))

    print(f"Monitor de Memória iniciado usando '{config_path}'. Ctrl+C para sair.")
    try:
        while True:
            executar_ciclo(config, estado_anterior, ultimo_alerta)
            if args.once:
                break
            time.sleep(intervalo)
    except KeyboardInterrupt:
        print("\nMonitoramento de memória encerrado.")


if __name__ == "__main__":
    main()
