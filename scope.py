#!/usr/bin/env python3
"""Scope gate: carrega o escopo de um programa e decide o que pode ser testado.

Todo outro script (recon.py, etc.) importa load_scope()/filter_in_scope() daqui
em vez de reimplementar a lógica — é o único lugar que decide "isso pode ser
atacado ou não".
"""
import sys
import fnmatch
from pathlib import Path

import yaml


class Scope:
    def __init__(self, data: dict, path: Path):
        self.path = path
        self.program = data.get("program", path.stem)
        self.handle = data.get("handle", "")
        self.policy_url = data.get("policy_url", "")
        self.in_scope = data.get("in_scope", []) or []
        self.out_of_scope = data.get("out_of_scope", []) or []
        rules = data.get("rules", {}) or {}
        self.allow_port_scan = bool(rules.get("allow_port_scan", False))
        self.allow_crawl = bool(rules.get("allow_crawl", False))
        self.allow_content_discovery = bool(rules.get("allow_content_discovery", False))
        self.allow_active_vuln_scan = bool(rules.get("allow_active_vuln_scan", False))
        self.rate_limit = int(rules.get("rate_limit", 5))
        self.notes = rules.get("notes", "")

        if not self.in_scope:
            raise ValueError(f"{path}: 'in_scope' está vazio — preencha antes de usar")

    def is_in_scope(self, host: str) -> bool:
        host = host.strip().lower().rstrip(".")
        if any(_match(host, pat) for pat in self.out_of_scope):
            return False
        return any(_match(host, pat) for pat in self.in_scope)

    def filter_in_scope(self, hosts):
        return [h for h in hosts if self.is_in_scope(h)]

    def banner(self) -> str:
        lines = [
            f"Programa: {self.program}",
            f"Política: {self.policy_url or '(sem URL cadastrada)'}",
            f"In-scope: {', '.join(self.in_scope)}",
            f"Out-of-scope: {', '.join(self.out_of_scope) or '(nenhum)'}",
            f"Port scan permitido: {'sim' if self.allow_port_scan else 'não'}",
            f"Crawling permitido: {'sim' if self.allow_crawl else 'não'}",
            f"Content discovery (fuzzing) permitido: {'sim' if self.allow_content_discovery else 'não'}",
            f"Scan ativo de vuln permitido: {'sim' if self.allow_active_vuln_scan else 'não'}",
            f"Rate limit configurado: {self.rate_limit} req/s",
        ]
        if self.notes:
            lines.append(f"Notas: {self.notes.strip()}")
        return "\n".join(lines)


def _match(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


def load_scope(path) -> Scope:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Arquivo de escopo não encontrado: {path}\n"
            f"Copie programs/_template.yaml para {path} e preencha com dados reais."
        )
    with path.open() as f:
        data = yaml.safe_load(f)
    return Scope(data, path)


def _cli():
    import argparse

    ap = argparse.ArgumentParser(description="Consulta/valida um arquivo de escopo")
    ap.add_argument("scope_file", help="ex: programs/example.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("show", help="Mostra o resumo do escopo")

    p_check = sub.add_parser("check", help="Verifica se um host está em escopo")
    p_check.add_argument("host")

    p_filter = sub.add_parser("filter", help="Filtra uma lista de hosts (stdin, um por linha)")

    args = ap.parse_args()
    scope = load_scope(args.scope_file)

    if args.cmd == "show":
        print(scope.banner())
    elif args.cmd == "check":
        ok = scope.is_in_scope(args.host)
        print("IN SCOPE" if ok else "OUT OF SCOPE")
        sys.exit(0 if ok else 1)
    elif args.cmd == "filter":
        hosts = [line.strip() for line in sys.stdin if line.strip()]
        for h in scope.filter_in_scope(hosts):
            print(h)


if __name__ == "__main__":
    _cli()
