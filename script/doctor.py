#!/usr/bin/env python3
"""Probe the development toolchain and report what each tool unlocks.

Runs as `cargo make doctor`. The bare command is a read-only report and
always exits 0. Each missing entry shows a copy-pasteable shell command to
install the tool, a descriptive note (version constraints, in-repo readme
pointers, ...), and a clickable hyperlink to the tool's install documentation
(OSC 8 on terminals, bare URL when piped). The header names the shell the
commands are written for (from $SHELL on Linux/macOS, PowerShell/cmd on
Windows).

The `install` subcommand installs missing tools, restricted to user-level,
deterministic recipes (rustup/cargo) — it never uses sudo and never touches
system packages; tools without such a recipe are reported with their manual
install hint instead.

Install commands and notes are OS-specific (Linux / macOS / Windows). Set
DOCTOR_OS to linux|macos|windows to preview another platform's hints.

  doctor.py                      # read-only report
  doctor.py install --dry-run    # print the install plan only
  doctor.py install              # install missing user-level tools
  doctor.py install --only wasm-target,nightly
"""
import argparse
import os
import platform as platform_module
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "script" / "lib"))
from cli import normalized_argv  # noqa: E402
from output import (  # noqa: E402
    bad,
    bold,
    cmd as echo_cmd,
    dim,
    error,
    fail,
    good,
    highlight,
    link,
    status,
    warn,
)

Probe = Callable[[], Tuple[bool, str]]
Hints = Dict[str, str]  # "linux" / "macos" / "windows"


def per_os(linux: str, macos: Optional[str] = None, windows: Optional[str] = None) -> Hints:
    """Per-OS text; macOS/Windows default to the Linux one, "" hides it."""
    return {
        "linux": linux,
        "macos": macos if macos is not None else linux,
        "windows": windows if windows is not None else linux,
    }


def platform_key() -> str:
    override = os.environ.get("DOCTOR_OS")
    if override:
        return override
    return {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(
        platform_module.system(), "linux"
    )


def shell_name(os_key: str) -> str:
    """The shell the printed install commands are written for."""
    if os.environ.get("DOCTOR_OS"):
        # Previewing another platform: name its assumed shell, not ours.
        return {"linux": "bash", "macos": "zsh", "windows": "PowerShell / cmd"}.get(
            os_key, "POSIX sh"
        )
    if os_key == "windows":
        return "PowerShell / cmd"
    shell = os.environ.get("SHELL", "")
    return Path(shell).name if shell else "POSIX sh"


class Entry:
    def __init__(
        self,
        entry_id: str,
        name: str,
        required: bool,
        probe: Probe,
        unlocks: str,
        cmd: Optional[Hints] = None,
        note: Optional[Hints] = None,
        docs: Optional[str] = None,
        install: Optional[List[List[str]]] = None,
    ):
        self.id = entry_id
        self.name = name
        self.required = required
        self.probe = probe
        self.unlocks = unlocks
        # Per-OS shell command that installs the tool ("" = no single command).
        self.cmd = cmd or {}
        # Per-OS descriptive note shown next to the command, or as the
        # install hint when there is no command.
        self.note = note or {}
        # URL of the tool's install documentation, shown as a hyperlink.
        self.docs = docs
        # User-level install recipe (list of argv commands), or None when the
        # install is platform/system-specific and stays a manual hint.
        self.install = install

    def cmd_for(self, os_key: str) -> str:
        # per_os fills all three keys; an explicit "" must survive (no
        # command/hint on that platform), so only fall back for unknown keys.
        value = self.cmd.get(os_key)
        return self.cmd.get("linux", "") if value is None else value

    def note_for(self, os_key: str) -> str:
        value = self.note.get(os_key)
        return self.note.get("linux", "") if value is None else value


def docs_link(url: str) -> str:
    """Hyperlink with a short scheme-less label: `link('rustup.rs', url)`."""
    label = re.sub(r"^https?://", "", url).rstrip("/")
    return link(label, url)


def print_missing_lines(entry: Entry, os_key: str, indent: str = "      ") -> None:
    """Print the install command, descriptive note, and doc link of a
    missing entry."""
    cmd_text = entry.cmd_for(os_key)
    note_text = entry.note_for(os_key)
    if cmd_text:
        # No `$` prompt or trailing comment: the line must paste into a
        # shell and run as-is.
        print(f"{indent}{highlight(cmd_text)}")
    if note_text:
        label = "note:" if cmd_text else "install:"
        print(f"{indent}{dim(label.ljust(8))} {note_text}")
    if entry.docs:
        print(f"{indent}{dim('docs:'.ljust(8))} {docs_link(entry.docs)}")


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def version_of(cmd: List[str], timeout: int = 15) -> str:
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    out = (proc.stdout or proc.stderr).strip()
    return out.splitlines()[0] if out else ""


def tool_probe(name: str, version_args=("--version",)) -> Probe:
    def probe() -> Tuple[bool, str]:
        found = which(name)
        return (bool(found), version_of([found, *version_args]) if found else "")

    return probe


def rustup_toolchains() -> List[str]:
    try:
        proc = subprocess.run(["rustup", "toolchain", "list"], text=True, capture_output=True, timeout=15)
        return proc.stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return []


def min_rust_version() -> str:
    data = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    return data["workspace"]["package"]["rust-version"]


def rustc_probe() -> Tuple[bool, str]:
    if not which("rustc"):
        return False, ""
    installed = version_of(["rustc", "--version"])  # "rustc 1.85.0 (hash date)"
    match = re.search(r"rustc (\d+)\.(\d+)", installed)
    if not match:
        return True, installed
    want = min_rust_version().split(".")
    ok = (int(match.group(1)), int(match.group(2))) >= (int(want[0]), int(want[1]))
    detail = installed if ok else f"{installed} (Cargo.toml requires rust >= {min_rust_version()})"
    return ok, detail


def python_probe() -> Tuple[bool, str]:
    # show_tasks.py / doctor.py use tomllib, which is stdlib from 3.11 on.
    py = which("python3") or which("python")
    if not py:
        return False, ""
    version = version_of([py, "--version"])  # "Python 3.11.2"
    match = re.search(r"(\d+)\.(\d+)", version)
    ok = bool(match) and (int(match.group(1)), int(match.group(2))) >= (3, 11)
    detail = version if ok else f"{version} (script automation needs >= 3.11 for tomllib)"
    return ok, detail


def component_probe(component: str, version_cmd: List[str]) -> Probe:
    def probe() -> Tuple[bool, str]:
        return (bool(which(version_cmd[0])), version_of(version_cmd))

    return probe


def wasm_target_probe() -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["rustup", "target", "list", "--installed"], text=True, capture_output=True, timeout=15
        )
        return "wasm32-unknown-unknown" in proc.stdout.splitlines(), "rustup target"
    except (OSError, subprocess.TimeoutExpired):
        return False, ""


def cargo_make_probe() -> Tuple[bool, str]:
    return (bool(which("cargo-make")), version_of(["cargo", "make", "--version"]))


def nightly_probe() -> Tuple[bool, str]:
    nightly = next((line for line in rustup_toolchains() if line.startswith("nightly")), "")
    return bool(nightly), nightly


def cargo_fuzz_probe() -> Tuple[bool, str]:
    return (bool(which("cargo-fuzz")), version_of(["cargo", "fuzz", "--version"]))


def llvm_tools_probe() -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["rustup", "component", "list", "--installed"], text=True, capture_output=True, timeout=15
        )
        found = any(line.startswith("llvm-tools") for line in proc.stdout.splitlines())
        return found, "rustup component"
    except (OSError, subprocess.TimeoutExpired):
        return False, ""


def cargo_llvm_cov_probe() -> Tuple[bool, str]:
    # cargo subcommand binaries expect the subcommand name as argv[1]; probe
    # through the cargo facade like cargo-make/cargo-fuzz above.
    return (bool(which("cargo-llvm-cov")), version_of(["cargo", "llvm-cov", "--version"]))


def collect_entries() -> List[Entry]:
    return [
        Entry("cargo", "cargo", True, tool_probe("cargo"), "all builds",
              cmd=per_os("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
                         windows="winget install Rustlang.Rustup"),
              docs="https://rustup.rs/"),
        Entry("rustc", f"rustc (>= {min_rust_version()})", True, rustc_probe, "all builds",
              cmd=per_os("rustup update"),
              note=per_os(f"Cargo.toml sets rust-version = \"{min_rust_version()}\" (edition 2024)"),
              docs="https://rust-lang.github.io/rustup/overrides.html"),
        Entry("rustfmt", "rustfmt component", True, component_probe("rustfmt", ["cargo", "fmt", "--version"]),
              "cargo make check-fmt",
              cmd=per_os("rustup component add rustfmt"),
              docs="https://github.com/rust-lang/rustfmt",
              install=[["rustup", "component", "add", "rustfmt"]]),
        Entry("clippy", "clippy component", True, component_probe("clippy", ["cargo", "clippy", "--version"]),
              "cargo make check-clippy",
              cmd=per_os("rustup component add clippy"),
              docs="https://github.com/rust-lang/rust-clippy",
              install=[["rustup", "component", "add", "clippy"]]),
        Entry("cargo-make", "cargo-make", True, cargo_make_probe, "cargo make <task>",
              cmd=per_os("cargo install cargo-make --locked"),
              docs="https://github.com/sagiegurari/cargo-make#installation",
              install=[["cargo", "install", "cargo-make", "--locked"]]),
        Entry("python3", "python3 (>= 3.11)", True, python_probe, "script automation (script/*.py)",
              cmd=per_os("sudo apt install python3",
                         macos="brew install python@3.12",
                         windows="winget install Python.Python.3.12"),
              note=per_os("Debian/Ubuntu; other distros via their package manager; tomllib needs 3.11+",
                          macos="", windows="or the python.org installer"),
              docs="https://www.python.org/downloads/"),
        Entry("wasm-target", "wasm32-unknown-unknown target", True, wasm_target_probe,
              "examples/gis-demo component build (build.sh, CI)",
              cmd=per_os("rustup target add wasm32-unknown-unknown"),
              docs="https://doc.rust-lang.org/rustc/platform/wasm32-unknown-unknown.html",
              install=[["rustup", "target", "add", "wasm32-unknown-unknown"]]),
        Entry("node", "node", False, tool_probe("node"), "web demo tests (examples/gis-demo/web/caf.test.mjs, CI js-host)",
              cmd=per_os("nvm install 22",
                         macos="brew install node@22",
                         windows="winget install OpenJS.NodeJS.LTS"),
              note=per_os("requires nvm (github.com/nvm-sh/nvm); or the nodejs.org installer; CI uses Node 22",
                          macos="", windows=""),
              docs="https://nodejs.org/en/download"),
        Entry("nightly", "nightly toolchain", False, nightly_probe, "cargo-fuzz (fuzz/ workspace)",
              cmd=per_os("rustup toolchain install nightly"),
              docs="https://rust-lang.github.io/rustup/concepts/toolchains.html",
              install=[["rustup", "toolchain", "install", "nightly"]]),
        Entry("cargo-fuzz", "cargo-fuzz", False, cargo_fuzz_probe,
              "fuzz/ targets (verify_bytes, manifest_decode, parse_container)",
              cmd=per_os("cargo install cargo-fuzz --locked"),
              note=per_os("runs on the nightly toolchain: cargo fuzz run verify_bytes"),
              docs="https://github.com/rust-fuzz/cargo-fuzz",
              install=[["cargo", "install", "cargo-fuzz", "--locked"]]),
        Entry("llvm-tools", "llvm-tools-preview component", False, llvm_tools_probe,
              "cargo make coverage (source-based instrumentation)",
              cmd=per_os("rustup component add llvm-tools-preview"),
              docs="https://doc.rust-lang.org/stable/rustc/instrument-coverage.html",
              install=[["rustup", "component", "add", "llvm-tools-preview"]]),
        Entry("cargo-llvm-cov", "cargo-llvm-cov", False, cargo_llvm_cov_probe,
              "cargo make coverage",
              cmd=per_os("cargo install cargo-llvm-cov --locked"),
              docs="https://github.com/taiki-e/cargo-llvm-cov",
              install=[["cargo", "install", "cargo-llvm-cov", "--locked"]]),
    ]


def report(entries: List[Tuple[Entry, bool, str]], os_key: str) -> Tuple[int, int]:
    name_width = max(len(entry.name) for entry, _, _ in entries)
    missing_required = 0
    missing_optional = 0
    sections = (
        ("Required", "core build / check / test", True),
        ("Optional", "examples, web demo, fuzz, coverage", False),
    )
    for title, subtitle, required in sections:
        group = [(entry, ok, detail) for entry, ok, detail in entries if entry.required == required]
        found = sum(1 for _, ok, _ in group if ok)
        print()
        print(bold(f"{title} — {subtitle} ") + dim(f"({found}/{len(group)} found)"))
        for entry, ok, detail in group:
            if ok:
                mark = good("✓")
            elif required:
                mark = fail("✗")
                missing_required += 1
            else:
                mark = bad("!")
                missing_optional += 1
            print(f"  {mark} {entry.name.ljust(name_width)}  {detail or 'not found'}"
                  + dim(f" — {entry.unlocks}"))
            if not ok:
                print_missing_lines(entry, os_key)
    print()
    return missing_required, missing_optional


def cmd_report() -> int:
    os_key = platform_key()
    print()
    print(bold("CAF toolchain doctor"))
    print(f"  {dim('platform:')} {os_key}")
    print(f"  {dim('shell:')}    {highlight(shell_name(os_key))}"
          + dim("  — the install commands below are written for this shell"))
    print(f"  {dim('msrv:')}     rust {min_rust_version()} (Cargo.toml workspace rust-version)")
    if os.environ.get("DOCTOR_OS"):
        print(dim(f"  (previewing {os_key} hints via DOCTOR_OS)"))
    entries = [(entry, *entry.probe()) for entry in collect_entries()]
    missing_required, missing_optional = report(entries, os_key)
    if missing_required:
        status("Doctor", f"{missing_required} required tool(s) missing; install them first")
    elif missing_optional:
        status("Doctor", f"core toolchain ready; {missing_optional} optional tool(s) missing (see above)")
    else:
        status("Doctor", "all tools present")
    if missing_required or missing_optional:
        print(dim("install the user-level ones automatically:  cargo make doctor -- install [--dry-run]"))
    return 0


def cmd_install(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Install missing user-level tools (no sudo).")
    parser.add_argument("--only", default=None, help="Comma-separated entry ids to install.")
    parser.add_argument("--dry-run", action="store_true", help="Print the install plan only.")
    args = parser.parse_args(argv)

    os_key = platform_key()
    probed = [(entry, *entry.probe()) for entry in collect_entries()]
    missing = [(entry, detail) for entry, ok, detail in probed if not ok]
    if args.only:
        wanted = args.only.split(",")
        known = {entry.id for entry, _, _ in probed}
        unknown = [item for item in wanted if item not in known]
        if unknown:
            error(f"unknown ids: {', '.join(unknown)} (known: {', '.join(sorted(known)) or 'none'})")
            return 2
        missing = [(entry, detail) for entry, detail in missing if entry.id in wanted]

    installable = [(entry, detail) for entry, detail in missing if entry.install]
    manual = [(entry, detail) for entry, detail in missing if not entry.install]

    status("Plan", f"{len(installable)} to install, {len(manual)} manual")
    for entry, _detail in installable:
        for command in entry.install:
            echo_cmd(command)
    for entry, _detail in manual:
        print(dim(f"  manual: {entry.name}"))
        print_missing_lines(entry, os_key, indent="          ")
    if args.dry_run or not installable:
        return 0

    failed = 0
    for entry, _detail in installable:
        command_failed = False
        for command in entry.install:
            status("Installing", entry.name)
            echo_cmd(command)
            if subprocess.run(command, text=True).returncode != 0:
                command_failed = True
        # The probe is the source of truth: some installers exit non-zero
        # from a post-install action after the tool itself landed.
        if entry.probe()[0]:
            if command_failed:
                warn(f"{entry.name}: an installer command exited non-zero, but the tool is now available")
            status("Installed", entry.name)
        else:
            failed += 1
            error(f"failed to install {entry.name} ({entry.cmd_for(os_key) or entry.note_for(os_key)})")

    if manual:
        print(dim("still manual: " + ", ".join(entry.name for entry, _ in manual)))
    if failed:
        error(f"{failed} install(s) failed")
        return 1
    status("Finished", f"{len(installable)} installed, {len(manual)} need manual install")
    return 0


def main() -> int:
    argv = normalized_argv()
    if argv and argv[0] == "install":
        return cmd_install(argv[1:])
    return cmd_report()


if __name__ == "__main__":
    sys.exit(main())
