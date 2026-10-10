# Copyright keplertech contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
"""Turn a Pavona IP core into a flat SystemVerilog file list via fusesoc.

Each IP gets a throw-away wrapper core that depends on the IP plus the
top_egret constant packages (which satisfy the lowrisc:virtual_constants:*
cores). fusesoc is run in --setup mode only, and the generated .vc file is
rewritten into an absolute-path flist usable by najaeda and kepler-formal.
"""
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
IPS_FILE = Path(__file__).resolve().parent / "ips.txt"

# prim_generic:all carries the fusesoc mapping for the virtual prim cores.
MAPPINGS = ["lowrisc:prim_generic:all:0.1"]
PROVIDERS = [
    "lowrisc:egret_constants:top_pkg",
    "lowrisc:egret_constants:top_racl_pkg:0.1",
]
# Only needed by IPs depending on lowrisc:virtual_constants:rnd_cnst_pkg /
# lc_ctrl_token_pkg; they drag in flash_ctrl/otp_ctrl, so they are only
# added when the plain wrapper fails to resolve.
EXTRA_PROVIDERS = [
    "lowrisc:egret_constants:testing_rnd_cnst_pkg:0.1",
    "lowrisc:egret_constants:testing_lc_ctrl_token_pkg:0.1",
]


class FlistError(RuntimeError):
    pass


def read_ips(selected=None):
    """Return [(core_vlnv, top)] from ips.txt, optionally filtered by top."""
    ips = []
    for line in IPS_FILE.read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            core, top = line.split()
            ips.append((core, top))
    if selected:
        known = {top for _, top in ips}
        unknown = set(selected) - known
        if unknown:
            raise SystemExit(f"unknown IP(s): {', '.join(sorted(unknown))}")
        ips = [ip for ip in ips if ip[1] in selected]
    return ips


def _fusesoc():
    local = Path(sys.executable).with_name("fusesoc")
    return str(local) if local.exists() else (shutil.which("fusesoc") or "fusesoc")


def _write_wrapper(wrappers: Path, core: str, top: str, extra: bool) -> str:
    vlnv = f"keplertech:pavona:{top}_wrap:0.1"
    deps = [*PROVIDERS, *(EXTRA_PROVIDERS if extra else []), core]
    dep_lines = "\n".join(f"      - {d}" for d in deps)
    wdir = wrappers / top
    wdir.mkdir(parents=True, exist_ok=True)
    (wdir / f"{top}_wrap.core").write_text(f"""CAPI=2:
name: "{vlnv}"
filesets:
  deps:
    depend:
{dep_lines}
targets:
  default:
    filesets: [deps]
    toplevel: {top}
    default_tool: verilator
    parameters: [SYNTHESIS=true]
    tools:
      verilator:
        mode: lint-only
parameters:
  SYNTHESIS:
    datatype: bool
    paramtype: vlogdefine
""")
    return vlnv


def _run_fusesoc(core: str, top: str, build: Path, extra: bool):
    wrappers = build / "wrappers"
    build_root = build / top
    shutil.rmtree(build_root, ignore_errors=True)
    vlnv = _write_wrapper(wrappers, core, top, extra)
    cmd = [_fusesoc(), "--cores-root", str(REPO / "hw"), "--cores-root",
           str(wrappers / top), "run", "--target=default", "--setup",
           "--build-root", str(build_root)]
    cmd += [f"--mapping={m}" for m in MAPPINGS] + [vlnv]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise FlistError(f"fusesoc failed for {core}:\n{r.stderr[-3000:]}")


def make_flist(core: str, top: str, build: Path) -> Path:
    """Return <build>/<top>/<top>.flist, running fusesoc if needed."""
    build_root = build / top
    flist = build_root / f"{top}.flist"
    if flist.exists():
        return flist
    try:
        _run_fusesoc(core, top, build, extra=False)
    except FlistError:
        _run_fusesoc(core, top, build, extra=True)
    vc = next(build_root.glob("**/*.vc"))
    base = vc.parent
    out = []
    for raw in vc.read_text().splitlines():
        line = raw.strip()
        if line.startswith("+incdir+"):
            out.append(f"+incdir+{(base / line[8:]).resolve()}")
        elif line.startswith("+define+"):
            out.append(line)
        elif line.startswith("-D") and len(line) > 2:
            out.append("+define+" + line[2:])
        elif line.endswith((".sv", ".v", ".svh", ".vh")):
            out.append(str((base / line).resolve()))
    flist.write_text("\n".join(out) + "\n")
    return flist


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("ips", nargs="*", help="IP tops (default: all in ips.txt)")
    ap.add_argument("--build", type=Path,
                    default=Path(__file__).resolve().parent / "out" / "build")
    args = ap.parse_args()
    for core, top in read_ips(args.ips):
        try:
            print(f"{top}: {make_flist(core, top, args.build.resolve())}")
        except FlistError as e:
            print(f"{top}: FAILED\n{e}", file=sys.stderr)
