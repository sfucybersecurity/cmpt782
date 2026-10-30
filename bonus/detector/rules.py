"""
rules.py — YOUR signature detector for MCP tool-call INPUTS (Bonus Task A).

Input-side detection fires on the *attempt*, whether or not the exploit works.
Compare the lab's output-side check in backend.py (`exploit_indicators` inside
POST /api/attack), which only fires after `root:`, `FLAG{`, `sk_live_`, ...
already appear in the response.

How to work:
  1. Run `python bonus/detector/evaluate.py` and read the misses / FPs.
  2. Add or tune Rule(...) entries below (see framework.py for every field).
  3. Re-run. Repeat until recall is high AND the FP column is (near) zero.

The one starter rule below is deliberately naive. Keep it, fix it, or replace it.

Which parameters reach which sink (from backend.py — the vulnerable code you
are defending, which you must NOT edit (I will check it!)):
    git.git_clone(repo_url)                git.git_diff(repo_path, commit_range)
    git.git_log(repo_path, options)        -> shell string, subprocess.run(shell=True)
    aws.list_s3_buckets(profile, filters)  aws.describe_instances(region, instance_filters)
    aws.get_ec2_metadata(metadata_path)    -> shell string, subprocess.run(shell=True)
    file.read_file(filepath)  file.write_file(filepath, content)
    file.list_directory(directory)         -> open() / os.listdir() on the raw path
    db.query_users(username)  db.search_users(search_term)
                                           -> f-string into cursor.execute()
    deserialization.deserialize_object(serialized_data, format_type="pickle"|"yaml")
                                           -> pickle.loads(base64.b64decode(...)) / yaml.Loader
    deserialization.process_config(config_data)
                                           -> yaml.load(..., Loader=yaml.Loader)
    template.render_template(template_string)
                                           -> jinja2.Template(...).render()
    template.generate_report(name, report_template)
                                           -> report_template.format(name=name)
"""

import base64  # noqa: F401  (you will want these)
import os
import pickletools  # noqa: F401
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Detection, Rule, excerpt, run_rules, string_params, url_decode  # noqa: E402,F401

RULES = [
    # ---- command injection (git.*, aws.*) -------------------------------------
    # Starter rule — catches `;` chaining and nothing else. Run evaluate.py to see
    # what it misses. Think about: other shell metacharacters, $(...) and `...`,
    # newlines, and option injection (a value starting with "-" where a URL or
    # region is expected). For region / repo_url, an expect=True "shape" rule
    # (what a legit value looks like) is often stronger than a blocklist.
    Rule("cmdi-semicolon", "cmdi", ("git.*", "aws.*"), None, re.compile(r";")),

    # ---- path traversal (file.read_file / write_file / list_directory) ----------
    # TODO: ../ sequences, absolute paths to sensitive locations, and ENCODED
    #       traversal. Hint: normalize=url_decode, and scope `params` to the path
    #       argument only — write_file's `content` is not a path.

    # ---- SQL injection (db.*) -------------------------------------------------
    # TODO: tautologies, UNION SELECT, comment markers, stacked queries.
    #       Watch the benign corpus: o'brien and "C# developers" are legit input.

    # ---- SSTI / format string (template.*) --------------------------------------------
    # TODO: Jinja {{ }} / {% %}, object traversal (__class__, __mro__, __subclasses__,
    #       __globals__), and str.format field access like {name.__class__}.
    #       Watch the benign corpus: "Hello {{ name }}" is a legitimate template.
    #       (Rule.strip lets you remove allowed constructs before matching.)
]


def detect_deserialization(call):
    """
    TODO: insecure deserialization (server "deserialization").

    A keyword rule on the raw parameter will NOT work for pickles: the payload is
    base64, so `os` / `system` never appear in the text you're matching. You must
    normalize first — decode it the same way the sink does — and then decide.
      * YAML: look for python/ tags (both the `!!python/` shorthand and the
        verbatim `!<tag:yaml.org,2002:python/...>` form).
      * Pickle: base64-decode, then inspect. Byte-grepping for markers is a start;
        walking the opcodes with pickletools.genops() and asking "does this
        pickle import or call anything?" is much better. Note the benign corpus
        contains a legitimate pickle of plain data.
    Return a list of Detection(...) objects (empty list = no alert).
    """
    return []


def detect(call):
    """Entry point used by evaluate.py and scan.py. Return a list of Detections."""
    return run_rules(RULES, call) + detect_deserialization(call)
