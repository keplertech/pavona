# Copyright keplertech contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
"""Run kepler-formal SEC on every Pavona IP, RTL against itself.

The design is compared with an identical copy of itself, so a sound checker
can never find a difference: the sweep measures how much of each IP
kepler-formal can elaborate and prove (proved outputs / observed outputs).

Outputs, under --out (default keplertech/out/kepler):
  <ip>/kepler.log          kepler-formal stdout/stderr
  <ip>/result.json         parsed per-IP result
  summary.md, summary.json aggregated table
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pavona_flist  # noqa: E402

VERDICTS = [  # (status, pattern) in priority order, from KeplerFormal.cpp
    ("not_equivalent", re.compile(r"SEC found a counterexample at k = (\d+)")),
    ("proved", re.compile(r"SEC proved .*?equivalence at k = (\d+)")),
    ("partial", re.compile(r"SEC partially proved equivalence at k = (\d+)")),
    ("inconclusive", re.compile(r"SEC verification did not produce a proof or counterexample")),
]
COVERAGE = re.compile(r"SEC checked-output coverage: [\d.]+% \((\d+)/(\d+)")
PARTIAL = re.compile(r"partially proved equivalence at k = \d+: (\d+)/(\d+) outputs proved")
LOAD_FAIL = re.compile(r"Netlist loading failed")
ERROR_LINE = re.compile(r"error: |Unsupported error: |\[critical\]")


def kepler_version(kepler: str) -> str:
    r = subprocess.run([kepler, "--version"], capture_output=True, text=True)
    return " ".join(l.strip() for l in (r.stdout + r.stderr).splitlines()
                    if "hash" in l or "version" in l)


def parse_log(text: str) -> dict:
    res = {}
    for status, pat in VERDICTS:
        m = pat.search(text)
        if m:
            res.update(status=status, k=int(m.group(1)) if m.groups() else None)
            break
    m = PARTIAL.search(text)
    if m:
        res.update(proved=int(m.group(1)), outputs=int(m.group(2)))
    elif res.get("status") == "proved":
        m = COVERAGE.search(text)
        if m:
            res.update(proved=int(m.group(1)), outputs=int(m.group(2)))
    if "status" not in res:
        res["status"] = "load_fail" if LOAD_FAIL.search(text) else "error"
    errs = [l.strip() for l in text.splitlines()
            if ERROR_LINE.search(l) and not l.lstrip().startswith("- ")]
    if errs and res["status"] in ("load_fail", "error"):
        # Specific slang/naja messages first, the generic [critical] last.
        errs.sort(key=lambda l: "[critical]" in l)
        res["first_errors"] = errs[:5]
    res["unsupported"] = sorted({m.group(1) for m in re.finditer(
        r"Unsupported error: ([^\n]{0,160})", text)})[:10]
    return res


def run_one(kepler, extra_args, core, top, build, out, timeout):
    d = out / top
    d.mkdir(parents=True, exist_ok=True)
    res = {"ip": top, "core": core}
    try:
        flist = pavona_flist.make_flist(core, top, build)
    except pavona_flist.FlistError as e:
        res.update(status="fusesoc_fail", first_errors=[str(e)[-500:]])
        (d / "result.json").write_text(json.dumps(res, indent=1))
        return res
    cmd = [kepler, "-sv", "--sv_design1_flist", str(flist), "--sv_design1_top", top,
           "--sv_design2_flist", str(flist), "--sv_design2_top", top,
           "-v", "sec", *extra_args]
    res["command"] = " ".join(cmd)
    t0 = time.time()
    with open(d / "kepler.log", "w") as log:
        try:
            p = subprocess.run(cmd, cwd=d, stdout=log, stderr=subprocess.STDOUT,
                               timeout=timeout)
            res["exit"] = p.returncode
        except subprocess.TimeoutExpired:
            res["exit"] = None
    res["seconds"] = round(time.time() - t0, 1)
    res.update(parse_log((d / "kepler.log").read_text(errors="replace")))
    if res["exit"] is None and res["status"] in ("error", "load_fail"):
        res["status"] = "timeout"
    (d / "result.json").write_text(json.dumps(res, indent=1))
    return res


def note(r):
    if r.get("first_errors"):
        msg = r["first_errors"][0]
    elif r.get("unsupported"):
        msg = "unsupported: " + r["unsupported"][0]
    else:
        return ""
    return msg[-140:].replace("|", "\\|")


def write_summary(results, out, version, extra_args):
    rows = sorted(results, key=lambda r: r["ip"])
    ran = [r for r in rows if "outputs" in r]
    tot_p = sum(r["proved"] for r in ran)
    tot_o = sum(r["outputs"] for r in ran)
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    md = [f"# kepler-formal SEC self-check ({version})", "",
          f"Extra arguments: `{' '.join(extra_args) or '(none)'}`", "",
          "Status: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
          "",
          f"Proved outputs over IPs reaching a verdict: {tot_p}/{tot_o}"
          + (f" ({100 * tot_p / tot_o:.1f}%)" if tot_o else ""), "",
          "| IP | status | proved/outputs | % | seconds | note |",
          "|---|---|---:|---:|---:|---|"]
    for r in rows:
        po = f"{r['proved']}/{r['outputs']}" if "outputs" in r else ""
        pct = f"{100 * r['proved'] / r['outputs']:.1f}" if r.get("outputs") else ""
        md.append(f"| {r['ip']} | {r['status']} | {po} | {pct} | "
                  f"{r.get('seconds', '')} | {note(r)} |")
    md.append("")
    (out / "summary.md").write_text("\n".join(md))
    (out / "summary.json").write_text(json.dumps(
        {"kepler_formal": version, "extra_args": extra_args, "results": results},
        indent=1))
    print("\n".join(md))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Arguments after '--' are passed to kepler-formal "
               "(e.g. -- --sec-engine k_induction -k 8).")
    ap.add_argument("ips", nargs="*", help="IP tops (default: all in ips.txt)")
    ap.add_argument("--kepler", default=os.environ.get("KEPLER_FORMAL", "kepler-formal"),
                    help="kepler-formal binary (default: $KEPLER_FORMAL or PATH)")
    ap.add_argument("-j", "--jobs", type=int, default=1,
                    help="parallel runs (default 1; concurrent runs have shown "
                         "spurious file-list errors)")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per IP")
    ap.add_argument("--out", type=Path, default=HERE / "out" / "kepler")
    ap.add_argument("--build", type=Path, default=HERE / "out" / "build")
    argv = sys.argv[1:]
    extra = argv[argv.index("--") + 1:] if "--" in argv else []
    args = ap.parse_args(argv[:argv.index("--")] if "--" in argv else argv)

    out, build = args.out.resolve(), args.build.resolve()
    version = kepler_version(args.kepler)
    print(f"kepler-formal: {version}")
    ips = pavona_flist.read_ips(args.ips)
    for core, top in ips:  # fusesoc up front, serially
        try:
            pavona_flist.make_flist(core, top, build)
        except pavona_flist.FlistError as e:
            print(f"{top}: {e}", file=sys.stderr)
    with ThreadPoolExecutor(args.jobs) as pool:
        futs = [pool.submit(run_one, args.kepler, extra, c, t, build, out, args.timeout)
                for c, t in ips]
        results = []
        for f in futs:
            r = f.result()
            po = f" {r['proved']}/{r['outputs']}" if "outputs" in r else ""
            print(f"{r['ip']}: {r['status']}{po} ({r.get('seconds', '-')} s)", flush=True)
            results.append(r)
    write_summary(results, out, version, extra)


if __name__ == "__main__":
    main()
