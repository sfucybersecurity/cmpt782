"""
evaluate.py — score a behavioral / policy detector (Bonus Task B).

Replays the WHOLE labeled corpus through one BehavioralDetector in timestamp
order (state and sequence matter), then scores the ssrf / logic / auth classes.

Scoring is per INCIDENT: some attacks are a sequence of calls that are each
harmless on their own (a burst of transfers, request-then-reset, verify-then-
check). Records that share an "incident" id are one attack, and it counts as
detected if your detector alerts on ANY of its calls. False positives are
counted per benign call.

Usage:
    python bonus/behavioral/evaluate.py                       # your behavioral/policy.py
    python bonus/behavioral/evaluate.py --policy path/to/other_policy.py
    python bonus/behavioral/evaluate.py --corpus path/to/dir
    python bonus/behavioral/evaluate.py --trace               # print every alert in order
"""

import argparse
import importlib.util
import os
import sys
from collections import OrderedDict, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "detector")))
import logsource  # noqa: E402  (shared loader lives in detector/)

CLASSES_B = ["ssrf", "logic", "auth"]


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pct(num, den):
    return "%5.0f%%" % (100.0 * num / den) if den else "    - "


def describe(call):
    params = ", ".join("%s=%r" % (k, v if not isinstance(v, str) or len(v) < 50 else v[:47] + "...")
                       for k, v in (call.get("parameters") or {}).items())
    return "%s %s.%s(%s)" % (call.get("student_id"), call.get("server"), call.get("tool"), params)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", default=os.path.join(HERE, "policy.py"),
                    help="module exposing BehavioralDetector with process(call) -> [alerts]")
    ap.add_argument("--corpus", default=os.path.normpath(os.path.join(HERE, "..", "corpus")))
    ap.add_argument("--trace", action="store_true", help="print the timeline with every alert")
    args = ap.parse_args()

    policy = load_module(args.policy, "student_policy")
    corpus = logsource.load_corpus(args.corpus)
    if not corpus:
        sys.exit("No corpus found under %s" % args.corpus)
    corpus.sort(key=lambda c: c.get("timestamp") or "")   # timeline order — state matters

    detector = policy.BehavioralDetector()
    incidents = OrderedDict()                 # incident id -> {"class", "calls", "detected"}
    fp = defaultdict(int)
    false_pos = []
    rule_hits = defaultdict(lambda: [0, 0, ""])

    for i, call in enumerate(corpus):
        alerts = detector.process(call) or []
        is_attack = call.get("label") == "attack"
        for rid, cls in {(a.rule_id, a.vuln_class) for a in alerts}:
            rule_hits[rid][0 if is_attack else 1] += 1
            rule_hits[rid][2] = cls
        if args.trace and (alerts or call.get("vuln_class") in CLASSES_B):
            mark = "ATTACK" if is_attack else "benign"
            print("%-26s %-6s %s" % (call.get("timestamp"), mark, describe(call)))
            for a in alerts:
                print("%33s-> [%s] %s: %s" % ("", a.severity, a.rule_id, a.reason))

        if is_attack and call.get("vuln_class") in CLASSES_B:
            key = call.get("incident") or "record-%d" % i
            inc = incidents.setdefault(key, {"class": call["vuln_class"], "calls": [], "detected": False})
            inc["calls"].append(call)
            inc["detected"] = inc["detected"] or bool(alerts)
        elif call.get("label") == "benign" and alerts:
            for cls in {a.vuln_class for a in alerts}:
                fp[cls] += 1
            false_pos.append((call, alerts))

    caught = defaultdict(int)
    total = defaultdict(int)
    for inc in incidents.values():
        total[inc["class"]] += 1
        caught[inc["class"]] += inc["detected"]
    benign_n = sum(1 for c in corpus if c.get("label") == "benign")

    if args.trace:
        print()
    print("=" * 72)
    print("BONUS TASK B — Behavioral / Policy Detection Results")
    print("policy: %s" % os.path.relpath(args.policy))
    print("corpus: %d attack incidents (ssrf/logic/auth), %d benign calls" % (len(incidents), benign_n))
    print("=" * 72)
    print("%-8s %10s %8s %8s %8s %10s %8s" % ("class", "incidents", "caught", "missed", "FP", "precision", "recall"))
    print("-" * 72)
    for c in CLASSES_B:
        miss = total[c] - caught[c]
        print("%-8s %10d %8d %8d %8d %10s %8s" % (c, total[c], caught[c], miss, fp[c],
                                                pct(caught[c], caught[c] + fp[c]), pct(caught[c], total[c])))
    print("-" * 72)
    t_caught, t_total, t_fp = sum(caught.values()), sum(total.values()), len(false_pos)
    print("%-8s %10d %8d %8d %8d %10s %8s" % ("TOTAL", t_total, t_caught, t_total - t_caught, t_fp,
                                            pct(t_caught, t_caught + t_fp), pct(t_caught, t_total)))
    print("False-positive rate: %d / %d benign calls flagged (%s)" % (t_fp, benign_n, pct(t_fp, benign_n).strip()))

    if rule_hits:
        print("\nPer-rule hits (calls)")
        print("%-42s %-6s %8s %8s" % ("rule_id", "class", "attacks", "benign"))
        print("-" * 68)
        for rid in sorted(rule_hits, key=lambda r: (rule_hits[r][2], r)):
            a, b, cls = rule_hits[rid]
            print("%-42s %-6s %8d %8d%s" % (rid, cls, a, b, "   <-- noisy" if b else ""))

    missed = [(k, v) for k, v in incidents.items() if not v["detected"]]
    if missed:
        print("\nMissed incidents (false negatives):")
        for key, inc in missed:
            print("  [%s] %s  (%d call%s)" % (inc["class"], key, len(inc["calls"]), "s" if len(inc["calls"]) > 1 else ""))
            for call in inc["calls"]:
                print("      %s %s" % (call.get("timestamp"), describe(call)))
    if false_pos:
        print("\nBenign calls flagged (false positives):")
        for call, alerts in false_pos:
            print("  %s %s\n      tripped: %s" % (call.get("timestamp"), describe(call),
                                                ", ".join(sorted({a.rule_id for a in alerts}))))


if __name__ == "__main__":
    main()
