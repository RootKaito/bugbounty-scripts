#!/usr/bin/env python3
"""Cria/lista relatórios de achado, em um formato próximo ao que o HackerOne pede.

Uso:
  python3 report.py new programs/example.yaml --title "IDOR em /api/orders/:id"
  python3 report.py list programs/example.yaml
"""
import argparse
import re
import time
from pathlib import Path

from scope import load_scope

HERE = Path(__file__).parent

TEMPLATE = """\
---
program: {program}
status: draft   # draft | submitted | triaged | resolved | duplicate | informative
severity: ""    # sua estimativa: none/low/medium/high/critical (CVSS se souber)
target: ""      # URL/host exato testado
created: {date}
---

# {title}

## Resumo
(1-2 frases: o que é a falha e por que importa)

## Passos para reproduzir
1.
2.
3.

## Evidência
(prints, request/response, curl -- sempre contra o alvo em escopo)

## Impacto
(o que um atacante real conseguiria fazer com isso)

## Remediação sugerida


## Referências
- Política do programa: {policy_url}
"""


def slugify(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s or "sem-titulo"


def cmd_new(args):
    scope = load_scope(args.scope_file)
    program_dir = HERE / "findings" / Path(args.scope_file).stem
    program_dir.mkdir(parents=True, exist_ok=True)

    slug = slugify(args.title)
    path = program_dir / f"{slug}.md"
    if path.exists():
        path = program_dir / f"{slug}-{int(time.time())}.md"

    content = TEMPLATE.format(
        program=scope.program,
        date=time.strftime("%Y-%m-%d"),
        title=args.title,
        policy_url=scope.policy_url,
    )
    path.write_text(content)
    print(f"Criado: {path}")


def cmd_list(args):
    program_dir = HERE / "findings" / Path(args.scope_file).stem
    if not program_dir.exists():
        print("Nenhum achado registrado ainda para esse programa.")
        return
    for path in sorted(program_dir.glob("*.md")):
        text = path.read_text()
        status = re.search(r"^status:\s*(\S+)", text, re.MULTILINE)
        severity = re.search(r"^severity:\s*\"?([^\"\n]*)\"?", text, re.MULTILINE)
        title = re.search(r"^# (.+)$", text, re.MULTILINE)
        print(f"{path.name:50s} status={status.group(1) if status else '?':10s} "
              f"severity={severity.group(1) if severity else '':10s} "
              f"{title.group(1) if title else ''}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_new = sub.add_parser("new", help="cria um novo rascunho de achado")
    p_new.add_argument("scope_file")
    p_new.add_argument("--title", required=True)
    p_new.set_defaults(func=cmd_new)

    p_list = sub.add_parser("list", help="lista achados de um programa")
    p_list.add_argument("scope_file")
    p_list.set_defaults(func=cmd_list)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
