"""Renders findings: colour terminal report (rich) or JSON."""
from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import Finding

_STYLE = {"vuln": "bold red", "typosquat": "bold yellow", "unpinned": "dim"}
_LABEL = {"vuln": "VULNERABLE", "typosquat": "TYPOSQUAT?", "unpinned": "UNPINNED"}


def render_terminal(findings: list[Finding], scanned: int, console: Console) -> None:
    if not findings:
        console.print(
            f"[bold green]✓ DepShield:[/bold green] scanned {scanned} "
            "dependencies — no issues found."
        )
        return
    table = Table(title=f"DepShield findings ({len(findings)})")
    table.add_column("Severity")
    table.add_column("Package")
    table.add_column("Finding")
    for f in findings:
        dep = f.dependency
        pkg = f"{dep.name} {dep.version or dep.spec or ''}".strip()
        detail = f.title
        if f.advisory and f.advisory.fixed_versions:
            detail += f" — fixed in {', '.join(f.advisory.fixed_versions)}"
        table.add_row(
            f"[{_STYLE[f.kind]}]{_LABEL[f.kind]}[/{_STYLE[f.kind]}]",
            pkg,
            detail,
        )
    console.print(table)
    for f in findings:
        if f.detail:
            console.print(f"[dim]{f.dependency.name}: {f.detail}[/dim]")


def render_json(findings: list[Finding], scanned: int) -> str:
    return json.dumps(
        {
            "scanned": scanned,
            "findings": [
                {
                    "kind": f.kind,
                    "package": f.dependency.name,
                    "ecosystem": f.dependency.ecosystem,
                    "version": f.dependency.version,
                    "title": f.title,
                    "detail": f.detail,
                    "advisory_id": f.advisory.id if f.advisory else None,
                    "fixed_versions": (
                        f.advisory.fixed_versions if f.advisory else []
                    ),
                    "suggestion": f.suggestion,
                }
                for f in findings
            ],
        },
        indent=2,
    )
