"""
logsource.py — load MCP tool-call records from the available log sources.

Every loader returns a list of normalized "call records":
    {
      "server":     str,              # mcp_server
      "tool":       str,
      "parameters": dict,
      "timestamp":  str | None,       # ISO-8601
      "student_id": str | None,
      "label":      str | None,       # "attack" / "benign"   (labeled corpus only)
      "vuln_class": str | None,       # cmdi, path, ...       (labeled corpus only)
      "incident":   str | None,       # groups multi-call attacks (Task B corpus)
      "exploited":  bool | None,      # the lab's OUTPUT-side verdict, when known
    }

Sources (no extra infrastructure needed for any of them):
  1. JSONL files — the labeled corpus in corpus/, your own labeled files, or
     the live capture that proxy.py writes to logs/calls.jsonl.
  2. The lab's own SQLite `attack_log` table. backend.py's LabDatabase writes it
     on every /api/attack call to `mcp_lab_tracking.db` (LabDatabase.db_path),
     relative to the directory you started backend.py from — normally the repo
     root. The lab README's "data/mcp_lab.db" is stale; ignore it.

Command-line use — export your Task 15 history as a corpus file to label:
    python bonus/detector/logsource.py --db mcp_lab_tracking.db \\
        --student YOUR_ID --out bonus/corpus/attacks_mine.jsonl
Then open the file, fix each record's "label" / "vuln_class", and delete the
records you don't want. evaluate.py picks up every attacks*.jsonl / benign*.jsonl.
"""

import argparse
import glob
import json
import os
import sqlite3
import sys

DEFAULT_DB = "mcp_lab_tracking.db"

# Best-guess class for exported records; students correct these by hand.
_GUESS_CLASS = {
    ("git", None): "cmdi", ("aws", None): "cmdi", ("db", None): "sqli",
    ("deserialization", None): "deserial", ("template", None): "ssti",
    ("logic", None): "logic", ("auth", None): "auth",
    ("file", "fetch_url"): "ssrf", ("file", None): "path",
}


def _normalize(obj):
    """Accept corpus/proxy records ({server, tool}) or DB rows ({mcp_server, tool_name})."""
    params = obj.get("parameters")
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except (ValueError, TypeError):
            params = {"_raw": params}
    exploited = obj.get("exploited")
    return {
        "server": obj.get("server") or obj.get("mcp_server"),
        "tool": obj.get("tool") or obj.get("tool_name"),
        "parameters": params if isinstance(params, dict) else {},
        "timestamp": obj.get("timestamp"),
        "student_id": obj.get("student_id"),
        "label": obj.get("label"),
        "vuln_class": obj.get("vuln_class"),
        "incident": obj.get("incident"),
        "exploited": None if exploited is None else bool(exploited),
    }


def load_jsonl(path):
    """Load one JSONL file of call records (corpus file or proxy capture)."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(_normalize(json.loads(line)))
            except ValueError as e:
                raise ValueError("%s:%d is not valid JSON: %s" % (path, lineno, e))
    return records


def load_corpus(corpus_dir):
    """Load every attacks*.jsonl and benign*.jsonl in corpus_dir into one list."""
    records = []
    for pattern in ("attacks*.jsonl", "benign*.jsonl"):
        for path in sorted(glob.glob(os.path.join(corpus_dir, pattern))):
            records.extend(load_jsonl(path))
    return records


def load_attack_log(db_path=DEFAULT_DB, student_id=None):
    """
    Read the lab's attack_log table (LabDatabase in backend.py).
    Columns: id, timestamp, student_id, mcp_server, tool_name, parameters, exploited, output.
    Records are UNLABELED; `exploited` is the lab's output-side verdict.
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(
            "attack_log DB not found at %r. It is created as mcp_lab_tracking.db in the "
            "directory you ran backend.py from; pass its path with --db." % db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        sql = ("SELECT timestamp, student_id, mcp_server, tool_name, parameters, exploited "
               "FROM attack_log")
        args = ()
        if student_id:
            sql += " WHERE student_id = ?"
            args = (student_id,)
        rows = conn.execute(sql + " ORDER BY id", args).fetchall()
    finally:
        conn.close()
    return [_normalize(dict(r)) for r in rows]


def load_source(db=None, jsonl=None, student_id=None):
    """Convenience: load from --db and/or --jsonl, sorted into timeline order."""
    records = []
    if db:
        records.extend(load_attack_log(db, student_id))
    for path in jsonl or []:
        records.extend(r for r in load_jsonl(path)
                       if not student_id or r.get("student_id") == student_id)
    records.sort(key=lambda r: r.get("timestamp") or "")
    return records


def _export(args):
    records = load_attack_log(args.db, args.student)
    if not records:
        print("No attack_log rows%s." % (" for student %r" % args.student if args.student else ""))
        return
    with open(args.out, "w", encoding="utf-8") as f:
        for r in records:
            guess = _GUESS_CLASS.get((r["server"], r["tool"])) or _GUESS_CLASS.get((r["server"], None))
            f.write(json.dumps({
                "label": "attack", "vuln_class": guess or "unknown",
                "student_id": r["student_id"], "server": r["server"], "tool": r["tool"],
                "parameters": r["parameters"], "timestamp": r["timestamp"],
            }) + "\n")
    print("Exported %d records to %s — now review each label/vuln_class by hand." % (len(records), args.out))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Export attack_log rows to a corpus JSONL file for labeling.")
    ap.add_argument("--db", default=DEFAULT_DB, help="path to mcp_lab_tracking.db (default: %(default)s)")
    ap.add_argument("--student", help="only export this student_id")
    ap.add_argument("--out", required=True, help="output .jsonl (name it attacks_*.jsonl or benign_*.jsonl)")
    try:
        _export(ap.parse_args())
    except FileNotFoundError as e:
        sys.exit(str(e))
