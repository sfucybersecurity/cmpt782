# Lab 7 — Bonus Tasks: MCP Blue Team (Detection Engineering)

These two bonus tasks extend the MCP Security Lab from Tasks 15–16. In Task 15
you attacked the MCP tools; in Task 16 you **read the source and patched it**.
Here you do a third, different job: the vulnerable code keeps running exactly
as it is, and you defend it **operationally**, from the outside, by
*detecting* attacks in the tool-call traffic.

> **Ground rules**
> - Do **not** modify `backend.py` or `app.py`. All of your work lives in `bonus/`.
> - Nothing to install beyond the lab's existing `requirements.txt`; the bonus
>   code is Python standard library only (Python 3.8+).
> - No Docker, no extra services. The default workflow is fully offline.

---

## Setup: where the attacks are visible

Every MCP tool call in this lab is one HTTP request:

```
POST /api/attack   {"student_id": ..., "mcp_server": ..., "tool": ..., "parameters": {...}}
```

You can observe those calls three ways. Pick whichever suits you.

| Source | What it is | How to use it |
|---|---|---|
| **Labeled corpus** (default) | `corpus/attacks.jsonl` and `corpus/benign.jsonl`, hand-labeled calls | `evaluate.py` scores against these automatically |
| **The lab's own log** | `backend.py` records every call in the `attack_log` table of `mcp_lab_tracking.db`, which is created in the directory you started `backend.py` from | `python bonus/scan.py --db mcp_lab_tracking.db --student YOUR_ID` |
| **Live capture** (optional) | `proxy.py` is a transparent pass-through proxy that logs each call to `bonus/logs/calls.jsonl` and forwards it **unchanged** | see below |

**Live capture, scripted attacks:** run `python backend.py` as usual (:8085),
then `python bonus/proxy.py` (:8086), and send your requests to
`http://localhost:8086/api/attack`.

**Live capture, including the Streamlit UI:** `app.py` talks to :8085, so put
the proxy there and move the backend:

```bash
uvicorn backend:app --port 8095                                          # from the repo root
PROXY_PORT=8085 MCP_BACKEND=http://localhost:8095 python bonus/proxy.py
streamlit run app.py
python bonus/scan.py --jsonl bonus/logs/calls.jsonl --follow             # live alerts
```

The proxy never blocks or rewrites anything. Responses are byte-for-byte what
the backend sent.

### Bring your own Task 15 attacks

Your corpus should include the payloads **you** used in Task 15. Export them
from the lab's log, then label them by hand:

```bash
python bonus/detector/logsource.py --db mcp_lab_tracking.db --student YOUR_ID \
       --out bonus/corpus/attacks_mine.jsonl
```

Open the file, check each record's `label` (`attack` / `benign`) and
`vuln_class`, and delete anything irrelevant. Both evaluators load every
`attacks*.jsonl` and `benign*.jsonl` in `corpus/`. You can also add your own
benign examples (`benign_mine.jsonl`), which is the honest way to test your
false-positive rate.

Corpus record format (one JSON object per line):

```json
{"label": "benign", "vuln_class": "path", "student_id": "alice", "server": "file",
 "tool": "read_file", "parameters": {"filepath": "reports/summary.txt"},
 "timestamp": "2026-11-02T09:00:04"}
```

Some examples of **benign** traffic you'll find in the corpus. Your detectors
must stay quiet on these:

| tool | legitimate call |
|---|---|
| `git.git_clone` | `repo_url="git@github.com:sfucybersecurity/cmpt782.git"` |
| `aws.describe_instances` | `region="eu-west-2"`, `instance_filters="--filters Name=instance-state-name,Values=running"` |
| `file.write_file` | `filepath="output/notes.txt"`, `content="Action items; review A & B \| owner: Sam ..."` |
| `db.query_users` / `search_users` | `username="o'brien"`, `search_term="C# developers"` |
| `deserialization.deserialize_object` | a base64 pickle of a plain dict |
| `template.render_template` | `"Hello {{ name }}, your order has shipped"`, `"Total: {{ total\|round(2) }}"` |
| `file.fetch_url` | `url="https://api.github.com/repos/python/cpython"` |
| `logic.apply_discount` | `discount_code="SAVE10"`, and the typo `"save10"` |
| `auth.reset_password` | request a token, then use it ~4 minutes later |

---

## Bonus Task A: MCP Detection Engineering (signatures), 10%

**Vulnerability framing:** five of the lab's sinks (shell, filesystem, SQL,
deserializer, template engine) are reachable with a malicious *string*, so a
well-built signature can catch the attempt.

**Objective:** build an input-side signature detector that flags malicious
tool-call **parameters**, firing on the *attempt* whether or not the exploit
succeeds.

The lab already has a detector of sorts. Look at `exploit_indicators` inside
`POST /api/attack` in `backend.py`. It is **output-side**: it marks a call
"exploited" only if the *response* contains strings like `root:`, `FLAG{` or
`sk_live_`. That means it is silent when the attack fails, when the output is
encoded or truncated, and when the leaked data just doesn't match its list.
Your detector inspects the **inputs** instead.

**What you build:** your rules in `detector/rules.py`. `detector/framework.py`
gives you a small data-driven `Rule` engine (scope by tool and parameter,
normalize, strip allowed constructs, blocklist or "expected shape" mode).
Cover at least:

1. **Command injection** (`git.*`, `aws.*`): shell metacharacters and chaining,
   command substitution, and option/argument injection where a URL or region
   is expected.
2. **Path traversal** (`file.read_file`, `write_file`, `list_directory`): `../`,
   absolute paths to sensitive files, and *encoded* traversal.
3. **SQL injection** (`db.*`): tautologies, `UNION SELECT`, comment markers,
   stacked queries.
4. **Insecure deserialization** (`deserialization.*`): **normalize first.** The
   pickle arrives base64-encoded, so a keyword rule on the raw parameter sees
   nothing. Decode it the way the sink does, then decide. For YAML, catch
   Python object tags.
5. **SSTI / format string** (`template.*`): Jinja expressions, Python object
   traversal (`__class__`, `__mro__`, ...), and `str.format` field access.

**Run:** `python bonus/detector/evaluate.py`. It prints per-class TP / FN / FP,
precision and recall, a per-rule hit table, and every miss and false positive.
The starter rule is deliberately naive, so expect a low score at first.

**What to submit**
1. Your `detector/rules.py` (and any corpus files you added).
2. The full output of `python bonus/detector/evaluate.py`.
3. A write-up (about 1 page):
   - how you tuned your rules to reduce false positives: name at least two
     benign calls that tripped an earlier version, and say what you changed;
   - **one paragraph contrasting your input-side detection with the lab's
     output-side `exploit_indicators`**: what each sees, what each misses, and
     why catching the *attempt* matters. Evidence from
     `python bonus/scan.py --db ...` on your own Task 15 history is welcome.

**Weight: 10%.** Detection coverage across the five classes (4%), the
evaluation table and false-positive tuning (4%), the input-vs-output contrast
(2%). Rules are also run against a held-out set of variants, so detect the
*technique* rather than the exact corpus strings.

---

## Bonus Task B: Behavioral / Policy Detection, 10%

**Vulnerability framing:** some of the lab's attacks have **no malicious
string at all**. Every argument is well-formed. The abuse is in the *value*,
the *destination*, the *rate*, or the *sequence* of calls.

Examples: a discount code that exists but was never published; a transfer
whose amount makes no sense; many transfers from one account in a fraction of
a second; a URL that is perfectly valid but points at the cloud metadata
service; a permission check by a client that never presented a trustworthy
token. No regex over the arguments can tell these apart from legitimate use,
and reading the source (Task 16) doesn't detect anything at runtime.

**Objective:** build a stateful policy detector, `behavioral/policy.py`, that
alerts on (it detects only, it does not block):

1. **SSRF egress** (`file.fetch_url`): deny-by-default. Define an
   **allowlist** of destinations and alert on everything else, including
   non-`https` schemes, loopback / RFC1918 / link-local (`169.254.169.254`)
   addresses however they are spelled, and URLs that hide the real host. An
   allowlist of destinations, **not** a blocklist of payloads.
2. **Business-logic abuse** (`logic.*`): discount codes outside the published
   set; transfers whose amounts are invalid or exceed the (tracked) balance;
   bursts of transfers from one account. Read `transfer_funds` in
   `backend.py` and explain why a burst is dangerous.
3. **Auth workflow anomalies** (`auth.*`): privilege-sensitive
   `check_permissions` calls without a preceding *trustworthy* `verify_token`
   from the same client, and `reset_password` flows that don't look like a
   human receiving an email.

The detector is fed every call in **timeline order** through one instance, so
keep whatever state you need (balances, sessions, recent-call windows).
Scoring is per **incident**: a multi-call attack counts as caught if you alert
on any of its calls. False positives are counted per benign call.

**Run:** `python bonus/behavioral/evaluate.py` (add `--trace` to see your
alerts on the timeline).

**What to submit**
1. Your `behavioral/policy.py`, including your allowlist and policy definitions.
2. Evidence: the full output of `python bonus/behavioral/evaluate.py`, showing
   it fires on the abuse and stays quiet on the legitimate `logic` / `file` /
   `auth` calls.
3. A write-up (about 1 page):
   - **why signature detection (Task A) cannot catch these**: pick at least
     three of your rules and show a malicious and a legitimate call that are
     indistinguishable as strings;
   - for each behavioral rule, **what data it needs** that a stateless
     signature doesn't have (state, timeline, identity, a definition of
     "legitimate");
   - how this differs from the **static review you did in Task 16**.

**Weight: 10%.** SSRF egress policy (3%), business-logic and auth workflow
detection, including the race/overdraft reasoning (4%), the "why signatures
fail" analysis (3%).

---

## File map

```
bonus/
├── README.md               this handout
├── proxy.py                optional live capture (pass-through, detection only)
├── scan.py                 run your detectors over attack_log / captures; compares with the lab's verdict
├── corpus/                 labeled calls: attacks*.jsonl, benign*.jsonl
├── detector/               Task A
│   ├── rules.py            <-- YOUR signatures
│   ├── framework.py        Rule engine + normalizers (no need to edit)
│   ├── evaluate.py         scoring harness
│   └── logsource.py        loaders for corpus / attack_log / captures; exports your history
└── behavioral/             Task B
    ├── policy.py           <-- YOUR policy detector
    └── evaluate.py         scoring harness
```
