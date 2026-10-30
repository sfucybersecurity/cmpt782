"""
scan.py — run your detectors over REAL, unlabeled lab traffic.

Sources:
    --db PATH       the lab's attack_log table (mcp_lab_tracking.db, created in
                    the directory you started backend.py from)
    --jsonl PATH    a capture written by proxy.py (bonus/logs/calls.jsonl)
    --follow        with --jsonl: keep watching the file and alert live

For every call it prints your input-side alerts (Task A signatures + Task B
policy) next to the lab's own output-side verdict (`exploited`), then
cross-tabulates the two. Use that table in your write-ups: attempts you flagged
that the lab never marked as exploited are exactly what output-side detection
misses.

Usage:
    python bonus/scan.py --db mcp_lab_tracking.db --student YOUR_ID
    python bonus/scan.py --jsonl bonus/logs/calls.jsonl --follow
    python bonus/scan.py --db mcp_lab_tracking.db --rules bonus/detector/rules.py --policy bonus/behavioral/policy.py
"""

import argparse
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "detector"))
import logsource  # noqa: E402


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def short(params, limit=90):
    text = json.dumps(params, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit - 3] + "..."


class Scanner:
    def __init__(self, rules, policy):
        self.rules = rules
        self.behavioral = policy.BehavioralDetector()
        self.counts = {(f, e): 0 for f in (True, False) for e in (True, False, None)}

    def scan(self, call):
        findings = [("A", d.severity, d.rule_id, "%s=%s" % (d.parameter, d.excerpt))
                    for d in (self.rules.detect(call) or [])]
        findings += [("B", a.severity, a.rule_id, a.reason) for a in (self.behavioral.process(call) or [])]
        exploited = call.get("exploited")
        self.counts[(bool(findings), exploited)] += 1
        if findings or exploited:
            verdict = {True: "EXPLOITED", False: "not exploited", None: "exploited=?"}[exploited]
            print("%s  %-10s %s.%s %s   [lab: %s]" % (call.get("timestamp"), call.get("student_id"),
                                                    call.get("server"), call.get("tool"), short(call.get("parameters")),
                                                    verdict))
            for task, sev, rid, why in findings:
                print("    %s %-6s %-40s %s" % (task, sev, rid, why))
            if not findings:
                print("    (no input-side alert — the lab marked this exploited but your detectors were silent)")

    def summary(self, total):
        c = self.counts
        print("\n" + "=" * 72)
        print("Input-side alerts vs. the lab's output-side `exploited` verdict  (%d calls)" % total)
        print("=" * 72)
        print("%-28s %14s %16s %14s" % ("", "lab: exploited", "lab: not exploit.", "lab: unknown"))
        for flagged in (True, False):
            print("%-28s %14d %16d %14d" % ("your detectors alerted" if flagged else "your detectors silent",
                                            c[(flagged, True)], c[(flagged, False)], c[(flagged, None)]))
        print("\nAlerted but NOT marked exploited = attempts that output-side detection never sees.")
        print("Marked exploited but no alert   = gaps in your rules (or a lab indicator false positive).")


def follow(path, scanner, student=None):
    print("Watching %s — Ctrl-C to stop.\n" % path)
    while not os.path.exists(path):
        time.sleep(0.5)
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        n = 0
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                if line.strip():
                    call = logsource._normalize(json.loads(line))
                    if student and call.get("student_id") != student:
                        continue
                    scanner.scan(call)
                    n += 1
        except KeyboardInterrupt:
            scanner.summary(n)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", help="path to mcp_lab_tracking.db")
    ap.add_argument("--jsonl", action="append", help="proxy capture file (repeatable)")
    ap.add_argument("--student", help="only this student_id")
    ap.add_argument("--follow", action="store_true", help="tail the --jsonl file and alert live")
    ap.add_argument("--rules", default=os.path.join(HERE, "detector", "rules.py"))
    ap.add_argument("--policy", default=os.path.join(HERE, "behavioral", "policy.py"))
    args = ap.parse_args()
    if not args.db and not args.jsonl:
        ap.error("give --db and/or --jsonl")

    scanner = Scanner(load_module(args.rules, "scan_rules"), load_module(args.policy, "scan_policy"))
    if args.follow:
        if not args.jsonl or len(args.jsonl) != 1:
            ap.error("--follow needs exactly one --jsonl file")
        follow(args.jsonl[0], scanner, args.student)
        return
    try:
        records = logsource.load_source(args.db, args.jsonl, args.student)
    except FileNotFoundError as e:
        sys.exit(str(e))
    for call in records:
        scanner.scan(call)
    scanner.summary(len(records))


if __name__ == "__main__":
    main()
