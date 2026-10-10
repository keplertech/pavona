# Copyright keplertech contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
"""Load every Pavona IP with najaeda and report elaboration statistics.

Each IP is loaded in its own subprocess (one najaeda netlist per process),
in "default" mode (one compilation unit per file) and/or "single" mode
(all files in one compilation unit, like Verilator).

Outputs, under --out (default keplertech/out/najaeda):
  <mode>/<ip>/result.json            per-IP result
  <mode>/<ip>/naja_sv_diagnostics.log  najaeda/slang diagnostics
  <mode>/<ip>/log.txt                subprocess stdout/stderr
  summary.md, summary.json           aggregated table
"""
import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from importlib import metadata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pavona_flist  # noqa: E402

MODES = ("default", "single")


def first_errors(diag: Path, n=5):
    if not diag.exists():
        return []
    return [l for l in diag.read_text(errors="replace").splitlines()
            if 'severity="error"' in l][:n]


def run_one(core: str, top: str, mode: str, build: Path, outdir: Path):
    """Child process body: load one IP and write result.json in cwd."""
    from najaeda import instance_visitor, netlist
    res = {"ip": top, "core": core, "mode": mode}
    try:
        flist = pavona_flist.make_flist(core, top, build)
    except pavona_flist.FlistError as e:
        res.update(status="fusesoc_fail", error=str(e)[-2000:])
        return res
    netlist.reset()
    t0 = time.time()
    try:
        inst = netlist.load_system_verilog([], config=netlist.SystemVerilogConfig(
            flist=str(flist), top=top, suppress_warnings=["sign-conversion"],
            single_unit=(mode == "single")))
    except Exception as e:  # najaeda raises on slang/elaboration failure
        res.update(status="load_fail", error=str(e)[-2000:],
                   first_errors=first_errors(outdir / "naja_sv_diagnostics.log"))
        return res
    res.update(status="ok", seconds=round(time.time() - t0, 2))
    models, prims = Counter(), 0

    def cb(i):
        nonlocal prims
        models[i.get_model_name()] += 1
        prims += i.is_primitive()
    instance_visitor.visit(inst, instance_visitor.VisitorConfig(callback=cb))
    res.update(ports=inst.count_terms(), children=inst.count_child_instances(),
               instances=sum(models.values()), primitives=prims,
               hier_modules=len([m for m in models if not m.startswith("$")]),
               top_models=models.most_common(5))
    return res


def launch(core, top, mode, build, out, timeout):
    d = out / mode / top
    d.mkdir(parents=True, exist_ok=True)
    (d / "result.json").unlink(missing_ok=True)
    cmd = [sys.executable, __file__, "--one", core, top, mode, "--build", str(build)]
    with open(d / "log.txt", "w") as log:
        try:
            subprocess.run(cmd, cwd=d, stdout=log, stderr=subprocess.STDOUT,
                           timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"ip": top, "core": core, "mode": mode, "status": "timeout"}
    if (d / "result.json").exists():
        return json.loads((d / "result.json").read_text())
    return {"ip": top, "core": core, "mode": mode, "status": "crash",
            "error": (d / "log.txt").read_text(errors="replace")[-2000:]}


def short_error(r):
    lines = r.get("first_errors") or (r.get("error") or "").splitlines()
    if not lines:
        return ""
    msg = lines[0]
    if 'message="' in msg:
        msg = msg.split('message="', 1)[1].rstrip('"')
    return msg[:120].replace("|", "\\|")


def write_summary(results, out: Path):
    version = metadata.version("najaeda")
    md = [f"# najaeda sweep (najaeda {version})", ""]
    for mode in MODES:
        rows = sorted((r for r in results if r["mode"] == mode), key=lambda r: r["ip"])
        if not rows:
            continue
        ok = [r for r in rows if r["status"] == "ok"]
        md += [f"## {mode}: {len(ok)}/{len(rows)} loaded, "
               f"{sum(r['primitives'] for r in ok)} primitives", "",
               "| IP | status | load s | instances | primitives | modules | first error |",
               "|---|---|---:|---:|---:|---:|---|"]
        for r in rows:
            md.append(f"| {r['ip']} | {r['status']} | {r.get('seconds', '')} | "
                      f"{r.get('instances', '')} | {r.get('primitives', '')} | "
                      f"{r.get('hier_modules', '')} | {short_error(r)} |")
        md.append("")
    (out / "summary.md").write_text("\n".join(md))
    (out / "summary.json").write_text(json.dumps(
        {"najaeda": version, "results": results}, indent=1))
    print("\n".join(md))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ips", nargs="*", help="IP tops (default: all in ips.txt)")
    ap.add_argument("--mode", choices=[*MODES, "both"], default="both")
    ap.add_argument("-j", "--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=1800, help="seconds per IP")
    ap.add_argument("--out", type=Path, default=HERE / "out" / "najaeda")
    ap.add_argument("--build", type=Path, default=HERE / "out" / "build")
    ap.add_argument("--one", nargs=3, metavar=("CORE", "TOP", "MODE"),
                    help=argparse.SUPPRESS)
    args = ap.parse_args()
    build = args.build.resolve()

    if args.one:
        res = run_one(*args.one, build, Path.cwd())
        Path("result.json").write_text(json.dumps(res, indent=1))
        print("RESULT " + json.dumps(res))
        return

    out = args.out.resolve()
    ips = pavona_flist.read_ips(args.ips)
    # Generate file lists up front so parallel jobs never race on fusesoc.
    for core, top in ips:
        try:
            pavona_flist.make_flist(core, top, build)
        except pavona_flist.FlistError as e:
            print(f"{top}: {e}", file=sys.stderr)
    modes = MODES if args.mode == "both" else (args.mode,)
    jobs = [(c, t, m) for m in modes for c, t in ips]
    with ThreadPoolExecutor(args.jobs) as pool:
        futs = [pool.submit(launch, c, t, m, build, out, args.timeout) for c, t, m in jobs]
        results = []
        for f in futs:
            r = f.result()
            print(f"[{r['mode']}] {r['ip']}: {r['status']}", flush=True)
            results.append(r)
    write_summary(results, out)


if __name__ == "__main__":
    main()
