"""
evaluate.py — score a signature detector against the labeled corpus (Bonus Task A).

Replays every labeled call through rules.detect() and prints:
  * a per-class table: attacks, caught (TP), missed (FN), benign flagged (FP),
    precision and recall
  * a per-rule table: how often each rule fired on attacks vs. benign calls
  * the exact calls you missed and the benign calls you flagged

A detector that flags everything gets 100% recall and terrible precision, so
the FP column matters as much as the "caught" column.

Usage:
    python bonus/detector/evaluate.py                     # your detector/rules.py
    python bonus/detector/evaluate.py --rules path/to/other_rules.py
    python bonus/detector/evaluate.py --corpus path/to/dir   # attacks*.jsonl + benign*.jsonl
"""

import argparse
import importlib.util
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import logsource  # noqa: E402

# Task A owns the payload-carrying classes. ssrf / logic / auth belong to Task B.
CLASSES_A = ["cmdi", "path", "sqli", "deserial", "ssti"]


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
    return "%s.%s(%s)" % (call.get("server"), call.get("tool"), params)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", default=os.path.join(HERE, "rules.py"), help="detector module exposing detect(call)")
    ap.add_argument("--corpus", default=os.path.normpath(os.path.join(HERE, "..", "corpus")),
                    help="directory holding attacks*.jsonl and benign*.jsonl")
    args = ap.parse_args()

    rules = load_module(args.rules, "student_rules")
    corpus = logsource.load_corpus(args.corpus)
    if not corpus:
        sys.exit("No corpus found under %s" % args.corpus)

    attacks = [c for c in corpus if c.get("label") == "attack" and c.get("vuln_class") in CLASSES_A]
    # Every benign call counts: a signature rule must also stay quiet on legit
    # fetch_url / logic / auth traffic, not just on its own server.
    benign = [c for c in corpus if c.get("label") == "benign"]

    tp = defaultdict(int)
    fn = defaultdict(int)
    fp = defaultdict(int)                       # benign calls flagged, by class of the rule that fired
    rule_hits = defaultdict(lambda: [0, 0, ""])  # rule_id -> [attack hits, benign hits, class]
    misses, false_pos = [], []

    for call in attacks:
        dets = rules.detect(call) or []
        for rid in {(d.rule_id, d.vuln_class) for d in dets}:
            rule_hits[rid[0]][0] += 1
            rule_hits[rid[0]][2] = rid[1]
        if dets:
            tp[call["vuln_class"]] += 1
        else:
            fn[call["vuln_class"]] += 1
            misses.append(call)

    for call in benign:
        dets = rules.detect(call) or []
        for rid in {(d.rule_id, d.vuln_class) for d in dets}:
            rule_hits[rid[0]][1] += 1
            rule_hits[rid[0]][2] = rid[1]
        for cls in {d.vuln_class for d in dets}:
            fp[cls] += 1
        if dets:
            false_pos.append((call, dets))

    print("=" * 72)
    print("BONUS TASK A — Signature Detection Results")
    print("rules:  %s" % os.path.relpath(args.rules))
    print("corpus: %d attacks (Task A classes), %d benign calls" % (len(attacks), len(benign)))
    print("=" * 72)
    print("%-10s %8s %8s %8s %8s %10s %8s" % ("class", "attacks", "caught", "missed", "FP", "precision", "recall"))
    print("-" * 72)
    for c in CLASSES_A:
        n = tp[c] + fn[c]
        print("%-10s %8d %8d %8d %8d %10s %8s" % (c, n, tp[c], fn[c], fp[c], pct(tp[c], tp[c] + fp[c]), pct(tp[c], n)))
    print("-" * 72)
    total_tp, total_fn = sum(tp.values()), sum(fn.values())
    total_fp = len(false_pos)
    print("%-10s %8d %8d %8d %8d %10s %8s" % ("TOTAL", len(attacks), total_tp, total_fn, total_fp,
                                             pct(total_tp, total_tp + total_fp), pct(total_tp, len(attacks))))
    print("False-positive rate: %d / %d benign calls flagged (%s)"
          % (total_fp, len(benign), pct(total_fp, len(benign)).strip()))

    if rule_hits:
        print("\nPer-rule hits")
        print("%-34s %-9s %8s %8s" % ("rule_id", "class", "attacks", "benign"))
        print("-" * 62)
        for rid in sorted(rule_hits, key=lambda r: (rule_hits[r][2], r)):
            a, b, cls = rule_hits[rid]
            print("%-34s %-9s %8d %8d%s" % (rid, cls, a, b, "   <-- noisy" if b else ""))

    if misses:
        print("\nMissed attacks (false negatives):")
        for call in misses:
            print("  [%s] %s" % (call["vuln_class"], describe(call)))
    if false_pos:
        print("\nBenign calls flagged (false positives):")
        for call, dets in false_pos:
            print("  %s\n      tripped: %s" % (describe(call), ", ".join(sorted({d.rule_id for d in dets}))))


if __name__ == "__main__":
    main()
