"""
policy.py — YOUR behavioral / policy detector (Bonus Task B).

These attacks have NO malicious-looking string. Every argument is well-formed;
the abuse is in the VALUE (relative to policy), the DESTINATION, the RATE, or
the SEQUENCE of calls. So you detect with policy and state, not regexes.

The detector is STATEFUL. evaluate.py feeds every call through ONE instance in
timestamp order, so you can keep balances, sessions, recent-call windows, etc.
on `self`. Each call record looks like:
    {"server": "logic", "tool": "transfer_funds", "student_id": "alice",
     "timestamp": "2026-11-03T11:04:00", "parameters": {...}}

Relevant behaviour of the vulnerable code (backend.py — do NOT edit it):
  file.fetch_url(url)       requests.get(url, allow_redirects=True), any host/scheme
  logic.apply_discount(cart_total, discount_code)
                            accepts SAVE10, SAVE20 ... and an unpublished code
  logic.transfer_funds(from_account, to_account, amount)
                            `if balance >= amount: time.sleep(0.1); debit; credit`
                            starting balances: account1=1000, account2=500
  auth.verify_token(token)  jwt.decode(..., algorithms=["HS256", "none"]), weak secret
  auth.check_permissions(user_id, resource, action)
                            grants ANY action to ANY non-empty user_id
  auth.reset_password(email, reset_token="")
                            no token  -> returns a reset token (= md5(email)) in the response
                            token     -> resets if it equals md5(email)

Run `python bonus/behavioral/evaluate.py --trace` to watch your alerts on the timeline.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    rule_id: str
    vuln_class: str      # "ssrf" | "logic" | "auth"
    server: str
    tool: str
    reason: str
    severity: str        # "low" | "medium" | "high"


# ---------------------------------------------------------------------------
# Policy definitions — what "legitimate" means. Fill these in.
# ---------------------------------------------------------------------------
ALLOWED_FETCH_HOSTS = set()        # TODO: destinations fetch_url may reach (see benign corpus)
PUBLIC_DISCOUNT_CODES = set()      # TODO: the codes customers were actually given
INITIAL_BALANCES = {"account1": 1000.0, "account2": 500.0}


def parse_ts(call):
    """Timestamp of a call as a datetime (or None)."""
    raw = call.get("timestamp")
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "")) if raw else None
    except ValueError:
        return None


class BehavioralDetector:
    def __init__(self):
        self.reset()

    def reset(self):
        """Clear all state."""
        self.balances = dict(INITIAL_BALANCES)
        # TODO: whatever else you need to remember between calls

    def process(self, call):
        """Return a list of Alert for ONE call. Calls arrive in timeline order."""
        tool = call.get("tool")
        p = call.get("parameters") or {}
        if tool == "fetch_url":
            return self.check_fetch_url(call, p)
        if tool in ("apply_discount", "transfer_funds"):
            return self.check_logic(call, p)
        if tool in ("verify_token", "check_permissions", "reset_password"):
            return self.check_auth(call, p)
        return []

    def check_fetch_url(self, call, p):
        """
        TODO — SSRF egress policy. Deny by default: alert unless the destination
        is on your allowlist. Think about non-https schemes, loopback / RFC1918 /
        link-local (169.254.169.254) addresses, IPs spelled in other forms
        (decimal, hex, IPv6), and URLs whose real host hides after an '@'.
        A blocklist of bad strings is NOT what we're after here.
        """
        return []

    def check_logic(self, call, p):
        """
        TODO — business-logic abuse.
          * apply_discount: a code outside the published set.
          * transfer_funds: amounts that make no sense for a transfer, amounts
            the source account can't cover (track balances as transfers happen),
            and many transfers from one account in a very short window — read
            transfer_funds in backend.py and explain why that matters.
        """
        return []

    def check_auth(self, call, p):
        """
        TODO — auth workflow anomalies. Calls that don't fit the expected flow:
          * a privilege-sensitive check_permissions with no preceding, trustworthy
            verify_token from the same client (what makes a token untrustworthy
            even if the server accepts it?)
          * reset_password: what does the legit two-step flow look like in time,
            and what does it look like when the token was never emailed at all?
        """
        return []
