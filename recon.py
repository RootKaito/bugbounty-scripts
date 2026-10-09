#!/usr/bin/env python3
"""Orquestra recon para um programa de bug bounty, sempre filtrando por escopo.

Fases (cada uma grava um arquivo em output/<programa>/<timestamp>/), 1 e 2
rodam em paralelo pois são independentes:
  1. subdomínios     - passivo: crt.sh + subfinder + assetfinder (+ amass com --deep)
  2. urls históricas - passivo: gau (Wayback/CommonCrawl/OTX/URLScan)
  3. resolução DNS   - dnsx: remove hosts que não resolvem
  4. port discovery  - naabu (ativo, rápido)  [--ports]
  5. probe HTTP      - pdhttpx (ProjectDiscovery) se instalado, senão requests puro
  6. crawling        - katana (ativo)  [--crawl]
  7. content disc.   - ffuf (ativo, precisa de wordlist)  [--fuzz --wordlist]
  8. port scan       - nmap -sV nas portas que o naabu achou abertas (ativo)  [--ports]
  9. vuln scan       - nuclei, incluindo urls achadas pelo naabu (ativo)  [--nuclei]

Fases 4,6,7,8,9 são ativas contra o alvo e exigem --confirm, além da
permissão correspondente (allow_crawl/allow_content_discovery/
allow_port_scan/allow_active_vuln_scan) no arquivo de escopo. Rode sempre
`scope.py <arquivo> show` antes para reler a política do programa.

`amass` fica fora do default porque é a fonte mais lenta (chega a passar
de 1-2min mesmo em modo passivo) pro ganho que costuma dar sobre
crt.sh+subfinder+assetfinder; use --deep quando quiser mesmo assim.

No final, todo o output/<programa>/<timestamp>/ é compactado num único
.zip ao lado da pasta — é esse arquivo que você sobe pra análise.

Nota: o binário real do httpx (ProjectDiscovery) é chamado aqui de
"pdhttpx" porque "httpx" no PATH costuma ser outra ferramenta (o cliente
HTTP Python). Se instalar via go install, renomeie o binário:
  mv ~/go/bin/httpx ~/go/bin/pdhttpx
"""
import argparse
import concurrent.futures
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

from scope import load_scope

HERE = Path(__file__).parent

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

NAABU_PORTS = "80,443,8080,8443,8000,8008,8081,8888,3000,3001,5000,9000,9090,9443,8090,8161,10000"
HTTPS_LIKE_PORTS = {443, 8443, 9443, 10443}


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr)


def _host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]


# ---------- Fase 1: subdomínios (passivo) ----------

def passive_subdomains_crtsh(root_domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        entries = r.json()
    except Exception as e:
        log(f"crt.sh falhou para {root_domain}: {e}")
        return set()
    out = set()
    for e in entries:
        for name in e.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name:
                out.add(name)
    return out


def passive_subdomains_subfinder(root_domain: str) -> set[str]:
    if not have("subfinder"):
        return set()
    try:
        r = subprocess.run(
            ["subfinder", "-d", root_domain, "-silent"],
            capture_output=True, text=True, timeout=180,
        )
        return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except Exception as e:
        log(f"subfinder falhou para {root_domain}: {e}")
        return set()


def passive_subdomains_assetfinder(root_domain: str) -> set[str]:
    if not have("assetfinder"):
        return set()
    try:
        r = subprocess.run(
            ["assetfinder", "--subs-only", root_domain],
            capture_output=True, text=True, timeout=60,
        )
        return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except Exception as e:
        log(f"assetfinder falhou para {root_domain}: {e}")
        return set()


def passive_subdomains_amass(root_domain: str) -> set[str]:
    if not have("amass"):
        return set()
    try:
        r = subprocess.run(
            ["amass", "enum", "-passive", "-d", root_domain, "-silent"],
            capture_output=True, text=True, timeout=180,
        )
        return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except Exception as e:
        log(f"amass falhou para {root_domain}: {e}")
        return set()


def root_domains_from_scope(scope) -> list[str]:
    roots = set()
    for pat in scope.in_scope:
        roots.add(pat[2:] if pat.startswith("*.") else pat)
    return sorted(roots)


def enumerate_subdomains(scope, roots: list[str], outdir: Path, deep: bool) -> list[str]:
    sources = [passive_subdomains_crtsh, passive_subdomains_subfinder, passive_subdomains_assetfinder]
    if deep:
        sources.append(passive_subdomains_amass)
    log(f"Fase 1/9: subdomínios (passivo{', +amass' if deep else ''}, {len(sources)} fontes em paralelo)")
    found = set(roots)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources) * len(roots) or 1) as ex:
        futures = [ex.submit(src, root) for root in roots for src in sources]
        for fut in concurrent.futures.as_completed(futures):
            found |= fut.result()
    in_scope = sorted(scope.filter_in_scope(found))
    (outdir / "subdomains.txt").write_text("\n".join(in_scope) + "\n")
    log(f"  {len(found)} descobertos, {len(in_scope)} em escopo -> subdomains.txt")
    return in_scope


# ---------- Fase 2: URLs históricas (passivo) ----------

def historical_urls(scope, roots: list[str], outdir: Path) -> tuple[list[str], list[str]]:
    log("Fase 2/9: urls históricas (passivo: gau, em paralelo com a fase 1)")
    if not have("gau"):
        log("  gau não encontrado, pulando. (go install github.com/lc/gau/v2/cmd/gau@latest)")
        return [], []
    urls = set()

    def _run_gau(root):
        try:
            # --timeout limita cada request individual: se um provedor (ex:
            # web.archive.org) estiver lento/inacessível na sua rede, ele
            # falha rápido em vez de travar a fase inteira.
            r = subprocess.run(
                ["gau", "--subs", "--timeout", "20", root],
                capture_output=True, text=True, timeout=120,
            )
            return {l.strip() for l in r.stdout.splitlines() if l.strip()}
        except subprocess.TimeoutExpired:
            log(f"gau excedeu 120s para {root}, seguindo sem essa fonte")
            return set()
        except Exception as e:
            log(f"gau falhou para {root}: {e}")
            return set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(roots))) as ex:
        for result in ex.map(_run_gau, roots):
            urls |= result

    in_scope_urls = sorted(u for u in urls if scope.is_in_scope(_host_of(u)))
    extra_hosts = sorted(scope.filter_in_scope({_host_of(u) for u in in_scope_urls}))
    (outdir / "historical_urls.txt").write_text("\n".join(in_scope_urls) + "\n")
    log(f"  {len(urls)} urls, {len(in_scope_urls)} em escopo -> historical_urls.txt")
    return in_scope_urls, extra_hosts


# ---------- Fase 3: resolução DNS ----------

def resolve_hosts(hosts: list[str], outdir: Path) -> list[str]:
    log("Fase 3/9: resolução DNS (dnsx)")
    if not hosts:
        return hosts
    if not have("dnsx"):
        log("  dnsx não encontrado, pulando (segue sem filtrar). (go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest)")
        return hosts
    try:
        r = subprocess.run(
            ["dnsx", "-silent"], input="\n".join(hosts),
            capture_output=True, text=True, timeout=max(120, len(hosts) // 20),
        )
    except Exception as e:
        log(f"dnsx falhou: {e}")
        return hosts
    resolved = sorted({l.strip().lower() for l in r.stdout.splitlines() if l.strip()})
    (outdir / "resolved.txt").write_text("\n".join(resolved) + "\n")
    log(f"  {len(resolved)}/{len(hosts)} hosts resolvem -> resolved.txt")
    return resolved


# ---------- Fase 4: port discovery rápido (ativo) ----------

def discover_ports_naabu(scope, hosts: list[str], outdir: Path, confirm: bool) -> list[tuple[str, int]]:
    log("Fase 4/9: port discovery rápido (naabu)")
    if not scope.allow_port_scan:
        log("  Escopo marca allow_port_scan=false, pulando.")
        return []
    if not confirm:
        log("  Pulado: passe --ports --confirm para rodar (ação ativa contra o alvo).")
        return []
    if not have("naabu"):
        log("  naabu não encontrado, pulando. (go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest)")
        return []
    hosts = scope.filter_in_scope(hosts)
    if not hosts:
        return []
    try:
        r = subprocess.run(
            ["naabu", "-silent", "-p", NAABU_PORTS],
            input="\n".join(hosts), capture_output=True, text=True, timeout=300,
        )
    except Exception as e:
        log(f"naabu falhou: {e}")
        return []
    pairs = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        host, _, port = line.rpartition(":")
        if host and port.isdigit() and scope.is_in_scope(host):
            pairs.append((host, int(port)))
    (outdir / "naabu.txt").write_text("\n".join(f"{h}:{p}" for h, p in pairs) + "\n")
    log(f"  {len(pairs)} host:porta abertos -> naabu.txt")
    return pairs


# ---------- Fase 5: probe HTTP ----------

def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def _url_candidates(target: str) -> list[str]:
    if target.count(":") == 1:
        host, port_s = target.rsplit(":", 1)
        if port_s.isdigit():
            port = int(port_s)
            if port == 443:
                return [f"https://{host}"]
            if port == 80:
                return [f"http://{host}"]
            scheme = "https" if port in HTTPS_LIKE_PORTS else "http"
            other = "http" if scheme == "https" else "https"
            return [f"{scheme}://{host}:{port}", f"{other}://{host}:{port}"]
    return [f"https://{target}", f"http://{target}"]


def _probe_target_requests(target: str, timeout: int = 8) -> dict | None:
    for url in _url_candidates(target):
        try:
            resp = requests.get(
                url, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": "bugbounty-recon/1.0"},
            )
            return {
                "input": target,
                "url": str(resp.url),
                "status_code": resp.status_code,
                "title": _extract_title(resp.text),
                "server": resp.headers.get("Server", ""),
                "tech": [],
                "content_length": len(resp.content),
            }
        except requests.RequestException:
            continue
    return None


def _probe_targets_pdhttpx(targets: list[str]) -> list[dict] | None:
    if not have("pdhttpx"):
        return None
    try:
        r = subprocess.run(
            ["pdhttpx", "-silent", "-json", "-title", "-tech-detect", "-status-code"],
            input="\n".join(targets), capture_output=True, text=True, timeout=max(300, len(targets) // 5),
        )
    except Exception as e:
        log(f"pdhttpx falhou: {e}")
        return None
    results = []
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        results.append({
            "input": d.get("input", d.get("host", "")),
            "url": d.get("url", ""),
            "status_code": d.get("status_code"),
            "title": d.get("title", ""),
            "server": d.get("webserver", ""),
            "tech": d.get("tech", []),
            "content_length": d.get("content_length"),
        })
    return results


def probe_hosts(hosts: list[str], naabu_pairs: list[tuple[str, int]], outdir: Path, concurrency: int = 5) -> list[dict]:
    log("Fase 5/9: probe HTTP (pdhttpx se disponível, senão requests puro)")
    # Se o naabu achou portas não-padrão, probamos elas também; hosts sem
    # porta extra caem no fallback https/http padrão de sempre.
    extra_ports_by_host = {}
    for h, p in naabu_pairs:
        if p not in (80, 443):
            extra_ports_by_host.setdefault(h, set()).add(p)
    targets = set(hosts)
    for h, ports in extra_ports_by_host.items():
        for p in ports:
            targets.add(f"{h}:{p}")
    targets = sorted(targets)

    if not targets:
        return []
    results = _probe_targets_pdhttpx(targets)
    if results is None:
        results = []
        workers = max(1, min(10, concurrency))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for r in ex.map(_probe_target_requests, targets):
                if r:
                    results.append(r)
    (outdir / "probe.jsonl").write_text("\n".join(json.dumps(x) for x in results) + "\n")
    log(f"  {len(results)}/{len(targets)} alvos vivos -> probe.jsonl")
    return results


# ---------- Fase 6: crawling (ativo) ----------

def crawl_katana(scope, probe_results: list[dict], outdir: Path, confirm: bool) -> list[str]:
    log("Fase 6/9: crawling (katana)")
    if not scope.allow_crawl:
        log("  Escopo marca allow_crawl=false, pulando.")
        return []
    if not confirm:
        log("  Pulado: passe --crawl --confirm para rodar (ação ativa contra o alvo).")
        return []
    if not have("katana"):
        log("  katana não encontrado, pulando. (go install github.com/projectdiscovery/katana/cmd/katana@latest)")
        return []
    urls = [h["url"] for h in probe_results if h.get("url") and scope.is_in_scope(_host_of(h["url"]))]
    if not urls:
        return []
    try:
        r = subprocess.run(
            ["katana", "-silent", "-depth", "2", "-jc"], input="\n".join(urls),
            capture_output=True, text=True, timeout=300,
        )
    except Exception as e:
        log(f"katana falhou: {e}")
        return []
    crawled = sorted({l.strip() for l in r.stdout.splitlines() if l.strip() and scope.is_in_scope(_host_of(l))})
    (outdir / "crawled_urls.txt").write_text("\n".join(crawled) + "\n")
    log(f"  {len(crawled)} urls -> crawled_urls.txt")
    return crawled


# ---------- Fase 7: content discovery (ativo) ----------

def _pick_wordlist(explicit: str | None) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() else None
    for w in DEFAULT_WORDLISTS:
        if Path(w).exists():
            return w
    return None


def fuzz_content_ffuf(scope, probe_results: list[dict], outdir: Path, confirm: bool, wordlist: str | None):
    log("Fase 7/9: content discovery (ffuf)")
    if not scope.allow_content_discovery:
        log("  Escopo marca allow_content_discovery=false, pulando.")
        return
    if not confirm:
        log("  Pulado: passe --fuzz --confirm para rodar (ação ativa contra o alvo).")
        return
    if not have("ffuf"):
        log("  ffuf não encontrado, pulando. (go install github.com/ffuf/ffuf/v2@latest)")
        return
    wl = _pick_wordlist(wordlist)
    if not wl:
        log("  Nenhuma wordlist encontrada. Passe --wordlist <path> (ex: SecLists) para rodar esta fase.")
        return
    bases = sorted({h["url"].rstrip("/") for h in probe_results
                     if h.get("url") and scope.is_in_scope(_host_of(h["url"]))})
    for base in bases:
        out_file = outdir / f"ffuf_{_host_of(base)}.json"
        cmd = [
            "ffuf", "-u", f"{base}/FUZZ", "-w", wl, "-rate", str(scope.rate_limit),
            "-of", "json", "-o", str(out_file), "-mc", "200,204,301,302,307,401,403",
        ]
        log(f"  $ {' '.join(cmd)}")
        try:
            subprocess.run(cmd, timeout=600)
        except Exception as e:
            log(f"ffuf falhou para {base}: {e}")
    log(f"  resultados -> {outdir}/ffuf_*.json")


# ---------- Fase 8: port scan detalhado (ativo) ----------

def scan_ports_nmap(scope, hosts: list[str], naabu_pairs: list[tuple[str, int]], outdir: Path, confirm: bool):
    log("Fase 8/9: port scan detalhado (nmap -sV)")
    if not scope.allow_port_scan:
        log("  Escopo marca allow_port_scan=false, pulando.")
        return
    if not confirm:
        log("  Pulado: passe --ports --confirm para rodar (ação ativa contra o alvo).")
        return
    if not have("nmap"):
        log("  nmap não encontrado, pulando.")
        return
    hosts = scope.filter_in_scope(hosts)
    if not hosts:
        return
    out_file = outdir / "nmap.xml"
    if naabu_pairs:
        # Usa só as portas que o naabu já confirmou abertas em algum host:
        # bem mais rápido e preciso que um scan às cegas em 100 portas.
        ports = sorted({str(p) for _, p in naabu_pairs})
        cmd = ["nmap", "-sV", "-T2", "-p", ",".join(ports), "-oX", str(out_file), *hosts]
    else:
        cmd = ["nmap", "-sV", "-T2", "--top-ports", "100", "-oX", str(out_file), *hosts]
    log(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, timeout=1800)
    log(f"  -> {out_file}")


# ---------- Fase 9: vuln scan (ativo) ----------

def scan_vulns_nuclei(scope, probe_results: list[dict], extra_urls: list[str], outdir: Path, confirm: bool):
    log("Fase 9/9: vuln scan (nuclei)")
    if not scope.allow_active_vuln_scan:
        log("  Escopo marca allow_active_vuln_scan=false, pulando.")
        return
    if not confirm:
        log("  Pulado: passe --nuclei --confirm para rodar (ação ativa contra o alvo).")
        return
    if not have("nuclei"):
        log("  nuclei não encontrado, pulando.")
        return
    urls = {h.get("url") for h in probe_results if h.get("url")}
    urls |= set(extra_urls)
    urls = sorted(u for u in urls if u and scope.is_in_scope(_host_of(u)))
    if not urls:
        return
    out_file = outdir / "nuclei.jsonl"
    cmd = [
        # sem -l/-u: nuclei lê a lista de alvos do stdin
        "nuclei", "-jsonl", "-o", str(out_file),
        "-severity", "info,low,medium,high,critical",
        "-rate-limit", str(scope.rate_limit),
        "-tags", "cves,exposures,misconfiguration,tech,default-login",
    ]
    log(f"  $ {' '.join(cmd)}  ({len(urls)} urls)")
    subprocess.run(cmd, input="\n".join(urls), text=True, timeout=1800)
    log(f"  -> {out_file}")


def zip_output(outdir: Path) -> Path:
    archive_base = str(outdir)  # shutil adiciona .zip
    zip_path = Path(shutil.make_archive(archive_base, "zip", root_dir=outdir.parent, base_dir=outdir.name))
    return zip_path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scope_file", help="ex: programs/example.yaml")
    ap.add_argument("--deep", action="store_true", help="inclui amass -passive na fase 1 (mais lento, mais cobertura)")
    ap.add_argument("--crawl", action="store_true", help="roda crawling (katana) se o escopo permitir")
    ap.add_argument("--fuzz", action="store_true", help="roda content discovery (ffuf) se o escopo permitir")
    ap.add_argument("--wordlist", help="wordlist para o ffuf (padrão: procura SecLists/dirb instalados)")
    ap.add_argument("--ports", action="store_true", help="roda port discovery (naabu) + port scan (nmap) se o escopo permitir")
    ap.add_argument("--nuclei", action="store_true", help="roda vuln scan (nuclei) se o escopo permitir")
    ap.add_argument("--confirm", action="store_true",
                     help="confirma que você leu a política do programa e está autorizado a rodar ações ativas")
    ap.add_argument("--no-zip", action="store_true", help="não compacta o resultado em .zip no final")
    args = ap.parse_args()

    scope = load_scope(args.scope_file)
    print(scope.banner())
    print()

    active_flags = args.crawl or args.fuzz or args.ports or args.nuclei
    if active_flags and not args.confirm:
        print("Aviso: fases ativas pedidas sem --confirm. Serão puladas.", file=sys.stderr)

    ts = time.strftime("%Y%m%d-%H%M%S")
    outdir = HERE / "output" / Path(args.scope_file).stem / ts
    outdir.mkdir(parents=True, exist_ok=True)

    roots = root_domains_from_scope(scope)

    # Fases 1 e 2 não dependem uma da outra: rodam ao mesmo tempo.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        fut_subs = ex.submit(enumerate_subdomains, scope, roots, outdir, args.deep)
        fut_hist = ex.submit(historical_urls, scope, roots, outdir)
        hosts = fut_subs.result()
        hist_urls, extra_hosts = fut_hist.result()

    hosts = sorted(set(hosts) | set(extra_hosts))
    hosts = resolve_hosts(hosts, outdir)

    naabu_pairs = discover_ports_naabu(scope, hosts, outdir, args.confirm) if args.ports else []
    probe_results = probe_hosts(hosts, naabu_pairs, outdir, concurrency=scope.rate_limit)

    crawled = crawl_katana(scope, probe_results, outdir, args.confirm) if args.crawl else []
    if args.fuzz:
        fuzz_content_ffuf(scope, probe_results, outdir, args.confirm, args.wordlist)
    if args.ports:
        scan_ports_nmap(scope, hosts, naabu_pairs, outdir, args.confirm)
    if args.nuclei:
        scan_vulns_nuclei(scope, probe_results, hist_urls + crawled, outdir, args.confirm)

    log(f"Concluído. Resultados em {outdir}")

    if not args.no_zip:
        zip_path = zip_output(outdir)
        log(f"Zip pronto para upload: {zip_path}")
        print(zip_path)


if __name__ == "__main__":
    main()
