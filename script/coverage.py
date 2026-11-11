#!/usr/bin/env python3
"""Run cargo-llvm-cov and pretty-print per-crate totals + the report link.

Runs as `cargo make coverage`. Performs the workspace coverage run (llvm-cov's
own per-file table plus the HTML report), then summarizes line coverage per
crate, the overall total, and the report link. Extra args pass through to
cargo-llvm-cov:

  cargo make coverage                          # full run + summary
  cargo make coverage -- --fail-under-lines 80 # forwarded to llvm-cov
"""
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "script" / "lib"))
from cli import normalized_argv  # noqa: E402
from output import bad, bold, cmd, dim, good, highlight, link, warn  # noqa: E402

OUT_DIR = REPO_ROOT / "target" / "llvm-cov"


def run_coverage(args: List[str]) -> int:
    argv = [
        "cargo",
        "llvm-cov",
        "--workspace",
        "--html",
        "--output-dir",
        str(OUT_DIR),
        *args,
    ]
    cmd(argv)
    sys.stdout.flush()
    return subprocess.run(argv).returncode


def summary_json() -> Optional[dict]:
    proc = subprocess.run(
        ["cargo", "llvm-cov", "report", "--summary-only", "--json"],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def crate_of(filename: str) -> str:
    parts = Path(filename).parts
    if "crates" in parts:
        index = parts.index("crates")
        if index + 1 < len(parts):
            return parts[index + 1]
    return "(other)"


def paint_pct(percent: float) -> str:
    text = f"{percent:5.1f}%"
    if percent >= 90:
        return good(text)
    if percent >= 75:
        return highlight(text)
    return bad(text)


def print_summary(data: dict) -> None:
    per_crate: Dict[str, Tuple[int, int]] = {}
    files = data.get("data", [{}])[0].get("files", [])
    for file in files:
        lines = file["summary"]["lines"]
        crate = crate_of(file["filename"])
        covered, count = per_crate.get(crate, (0, 0))
        per_crate[crate] = (covered + lines["covered"], count + lines["count"])

    print()
    print(bold("Coverage by crate (lines)"))
    width = max(len(name) for name in per_crate)
    total_covered = total_count = 0
    for crate in sorted(per_crate):
        covered, count = per_crate[crate]
        total_covered += covered
        total_count += count
        percent = 100.0 * covered / count if count else 100.0
        print(
            f"  {crate.ljust(width)}  {paint_pct(percent)}  "
            + dim(f"({covered}/{count} lines)")
        )
    percent = 100.0 * total_covered / total_count if total_count else 100.0
    print("  " + dim("─" * (width + 22)))
    print(
        f"  {bold('TOTAL'.ljust(width))}  {paint_pct(percent)}  "
        + dim(f"({total_covered}/{total_count} lines)")
    )
    print()
    index = OUT_DIR / "html" / "index.html"
    print(f"  {dim('HTML report:')} {link(str(index), index.as_uri())}")
    print()


def main() -> int:
    args = normalized_argv()
    code = run_coverage(args)
    if code != 0:
        return code
    data = summary_json()
    if data is None:
        warn("per-crate summary unavailable; the HTML report was still written")
    else:
        print_summary(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
