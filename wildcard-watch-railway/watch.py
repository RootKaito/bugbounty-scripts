#!/usr/bin/env python3
"""Varre hackerone.com/opportunities/all por programas Bounty + escopo
Wildcard + boa response efficiency, e notifica Discord + Telegram só o
que for genuinamente novo desde a última execução.

Pensado pra rodar como job agendado (cron) no Railway: cada execução é
curta, sem estado em memória entre rodadas — todo o "o que já vi antes"
fica em STATE_PATH, que precisa ser um volume persistente.

A página (SPA React) abre num feed curado; clicar no chip "Popular now"
"Bounty" troca pra lista completa filtrável por tipo de programa. O
filtro "é wildcard?" é feito em Python sobre o texto de cada card já
carregado (ver parse_card) — não na UI da página, que é frágil (painel
de filtro varia com viewport, ids dinâmicos).
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

import requests
from playwright.sync_api import sync_playwright

URL = "https://hackerone.com/opportunities/all"
STATE_PATH = os.environ.get("STATE_PATH", "/data/seen_programs.json")
DISCORD_WEBHOOK_URL = os.environ["DISCORD_WEBHOOK_URL"]
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
MIN_RESPONSE_EFFICIENCY = int(os.environ.get("MIN_RESPONSE_EFFICIENCY", "70"))

KNOWN_ASSET_TYPES = [
    "Domain", "Wildcard", "Api", "AndroidPlayStore", "AndroidApk", "IosAppStore",
    "IosTestflight", "IosIpa", "WindowsMicrosoftStore", "SourceCode", "Executable",
    "SmartContract", "IpAddress", "Hardware", "OtherAsset", "AiModel",
    "AwsCloudConfig", "AzureCloudConfig", "Cidr",
]


def log(msg: str):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", file=sys.stderr)


# ---------- scraping ----------

def scrape_cards() -> list[dict]:
    with sync_playwright() as p:
        # --disable-dev-shm-usage: Docker limita /dev/shm a 64MB por
        # padrão, insuficiente pro Chromium — sem essa flag ele crasha
        # ("Target crashed") em containers como o do Railway.
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-dev-shm-usage", "--disable-gpu", "--no-sandbox"],
        )
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        log(f"abrindo {URL}")
        page.goto(URL, wait_until="networkidle", timeout=60000)

        page.get_by_role("button", name="Bounty", exact=True).click()
        page.wait_for_timeout(1500)

        target = None
        m = re.search(r"We found (\d+) opportunities", page.inner_text("body"))
        if m:
            target = int(m.group(1))
            log(f"alvo: {target} programas Bounty")

        stable_iters = 0
        last_count = -1
        for _ in range(200):  # teto de segurança
            count = page.locator("a:has-text('See details')").count()
            if count == last_count:
                stable_iters += 1
            else:
                stable_iters = 0
                last_count = count
            if target and count >= target:
                break
            if stable_iters >= 4:
                break
            page.evaluate("""
                window.scrollTo(0, document.body.scrollHeight);
                document.querySelectorAll('*').forEach(el => {
                    if (el.scrollHeight > el.clientHeight + 50) el.scrollTop = el.scrollHeight;
                });
            """)
            page.wait_for_timeout(1200)

        log(f"carregados {last_count} cards (alvo {target})")

        # innerText (não textContent): preserva quebra de linha entre
        # campos renderizados em blocos separados. textContent cola tudo
        # sem separador e corrompe números colados.
        cards = page.evaluate("""
            () => Array.from(document.querySelectorAll('a'))
                .filter(a => a.textContent.trim() === 'See details')
                .map(a => ({
                    url: a.href,
                    text: (a.closest('div')?.parentElement?.innerText || '').trim(),
                }))
        """)
        browser.close()
        return cards


def parse_money(token: str):
    token = token.strip().lstrip("$").replace(",", "")
    m = re.match(r"([\d.]+)\s*([kKmM]?)", token)
    if not m:
        return None
    val = float(m.group(1))
    suf = m.group(2).lower()
    if suf == "k":
        val *= 1_000
    elif suf == "m":
        val *= 1_000_000
    return int(val)


def parse_card(url: str, text: str) -> dict | None:
    handle = url.rstrip("/").split("/")[-1].split("?")[0]
    lines = [l.strip() for l in text.split("\n") if l.strip()]
    if not lines:
        return None
    joined = " ".join(lines)

    type_match = re.search(r"\b(Bounty|VDP)\b", joined)
    program_type = type_match.group(1) if type_match else None

    assets = {}
    for i, line in enumerate(lines[:-1]):
        if line in KNOWN_ASSET_TYPES and lines[i + 1].isdigit():
            assets[line] = int(lines[i + 1])

    bounty_min = bounty_max = None
    m = re.search(r"\$([\d.,]+[kKmM]?)\s*-\s*\$([\d.,]+[kKmM]?)", joined)
    if m:
        bounty_min, bounty_max = parse_money(m.group(1)), parse_money(m.group(2))
    else:
        m = re.search(r"\$([\d.,]+[kKmM]?)", joined)
        if m:
            bounty_min = bounty_max = parse_money(m.group(1))

    response_efficiency = None
    if len(lines) >= 2 and lines[-1] == "See details":
        m = re.match(r"^(\d{1,3})%$", lines[-2])
        if m:
            response_efficiency = int(m.group(1))

    return {
        "handle": handle,
        "name": lines[0] or handle,
        "url": url.split("?")[0],
        "program_type": program_type,
        "wildcard_count": assets.get("Wildcard", 0),
        "bounty_min": bounty_min,
        "bounty_max": bounty_max,
        "response_efficiency": response_efficiency,
    }


# ---------- state ----------

def load_state() -> dict:
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as f:
            return json.load(f)
    return {}


def save_state(state: dict):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_PATH)


# ---------- mensagem ----------

def fmt_money(n):
    return f"${n:,}" if n is not None else "?"


def build_message(p: dict) -> str:
    wc = p["wildcard_count"]
    scope = f"{wc} wildcard domain{'s' if wc != 1 else ''}"
    return (
        f"👁️ Nyarlathotep whispers...\n\n"
        f"🎯 {p['name']}\n"
        f"🌐 {scope}\n"
        f"💰 {fmt_money(p['bounty_min'])} – {fmt_money(p['bounty_max'])}\n"
        f"🔥 Good target\n\n"
        f"🔗 {p['url']}"
    )


# ---------- envio ----------

def notify_discord(content: str):
    r = requests.post(DISCORD_WEBHOOK_URL, json={"content": content}, timeout=15)
    r.raise_for_status()


def notify_telegram(content: str):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return
    r = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        json={"chat_id": TELEGRAM_CHAT_ID, "text": content},
        timeout=15,
    )
    r.raise_for_status()


# ---------- main ----------

def main():
    cards = scrape_cards()
    log(f"{len(cards)} cards extraídos")

    parsed = [parse_card(c["url"], c["text"]) for c in cards]
    candidates = [
        p for p in parsed
        if p and p["program_type"] == "Bounty"
        and p["wildcard_count"] > 0
        and (p["response_efficiency"] or 0) >= MIN_RESPONSE_EFFICIENCY
    ]
    log(f"{len(candidates)} passam no filtro (Bounty + Wildcard + resposta >= {MIN_RESPONSE_EFFICIENCY}%)")

    state = load_state()
    now = datetime.now(timezone.utc).isoformat()
    new_programs = []
    for p in candidates:
        if p["handle"] not in state:
            p["first_seen"] = now
            new_programs.append(p)
        else:
            p["first_seen"] = state[p["handle"]].get("first_seen", now)
        state[p["handle"]] = p

    log(f"{len(new_programs)} novos desde a última execução")
    for p in new_programs:
        msg = build_message(p)
        notify_discord(msg)
        notify_telegram(msg)
        log(f"  notificado: {p['name']}")

    save_state(state)
    log("concluído")


if __name__ == "__main__":
    main()
