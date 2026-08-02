"""kit/gaps.py: what the c7n-org run could NOT look at.

WHY THIS EXISTS
`c7n-org` runs a policy against N accounts x M regions. If an invocation
fails, that account-region-policy cell simply does not show up in the
output: there's no row saying "this could not be evaluated." And an account
that doesn't show up looks EXACTLY like a clean account: both have zero
findings. Nobody complains about that gap because nobody sees it. This
module turns the run's raw log into an explicit list of gaps, each with a
kind that tells the reader what action to take.

THE KIT'S RULE: AN ABSENCE IS NOT A ZERO
A gap that could not be classified is NEVER dropped or counted as "none of
the above, moving on." It falls into `unknown`, which is a first-class
kind: it shows up in both the human and machine renders like any other. A
new error kind falling into a silent drawer is exactly the bug this kit
exists to catch.

FORMATS VERIFIED AGAINST THE REAL SOURCE
The regexes below match the `log.warning`/`log.error` calls in
`tools/c7n_org/c7n_org/cli.py` in cloud-custodian/cloud-custodian (branch
`main`, commit 2b6a67cc8cc818909f87953ed964dda123bc5fe5 at the time of
writing, verified by reading the file, not guessed):
https://github.com/cloud-custodian/cloud-custodian/blob/main/tools/c7n_org/c7n_org/cli.py

  L1266-1268  log.warning('Access denied api:%s policy:%s account:%s region:%s',
                           e.operation_name, p.name, account['name'], region)
              fires ONLY when the code is the literal 'AccessDenied' (S3/IAM/
              STS). It aborts the rest of the policies in that file for that
              account and region, which is why it carries no error text,
              only the four positional keys.

  L1269-1270  log.error("Exception running policy:%s account:%s region:%s error:%s",
                         p.name, account['name'], region, e)
  L1275-1276  (same format, second except branch)
              the trailing `%s` is `str(exception)`. That's where the real
              AWS message lives: "because no identity-based/resource-based
              policy allows...", "Could not connect to the endpoint URL...",
              the ClientError codes, and so on. This is the line that does
              most of the classification work.

  L440-441    log.warning("Error running policy in %s @ %s exception: %s",
                           a['name'], r, f.exception())
              shows up when something fails BEFORE the policy runs (an
              unregistered custom filter, invalid YAML for that account). It
              carries no policy name, so the Gap marks it with a fixed name
              documented in POLICY_UNIDENTIFIED.

The phrases "because no identity-based policy allows" / "because no
resource-based policy allows" aren't from c7n: they're IAM's explicit deny
message (see AWS docs on "troubleshoot IAM policies") that AWS attaches
automatically to any AccessDenied when it can explain WHICH of the two
evaluations (role vs. resource) blocked it. Confirmed in production against
real KMS, S3, and Secrets Manager before writing this module.

If a format shows up in your output that this doesn't recognize, `classify`
sends it to `unknown` instead of losing it, but if that happens often, it's
a sign this file needs a new regex, not that something is "weird."
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# ─────────────────────────────────────────── c7n-org line formats

# Aborts the ENTIRE rest of the file for that account/region (see the
# docstring above). It carries no error text: the 'AccessDenied' code
# itself already says it all.
ACCESS_DENIED_RE = re.compile(
    r"Access denied api:(?P<api>\S+)\s+policy:(?P<policy>\S+)\s+"
    r"account:(?P<account>\S+)\s+region:(?P<region>\S+)"
)

# Failure BEFORE the policy runs (unregistered filter, invalid config for
# that account). Carries no policy name.
POLICY_LOAD_ERROR_RE = re.compile(
    r"Error running policy in (?P<account>\S+) @ (?P<region>\S+) exception: (?P<error>.*)"
)

# The common case: the policy ran and blew up. `error` is `str(exception)`.
POLICY_ERROR_RE = re.compile(
    r"Exception running policy:(?P<policy>\S+)\s+account:(?P<account>\S+)\s+"
    r"region:(?P<region>\S+)(?:\s+error:(?P<error>.*))?"
)

# Name used when the line carries no policy (POLICY_LOAD_ERROR_RE): the
# failure belongs to the WHOLE file, not a single rule.
POLICY_UNIDENTIFIED = "(unidentified, failed before the policy ran)"

# ─────────────────────────────────────── what the error TEXT says

# The module's single most valuable distinction. Both phrases are IAM's
# explicit deny message, verbatim:
#   "...because no identity-based policy allows..."  -> permission missing
#       on OUR OWN role. The team that runs c7n fixes it.
#   "...because no resource-based policy allows..."  -> our IAM is fine,
#       the RESOURCE's policy (a KMS key policy, an S3 bucket policy, an SQS
#       queue policy, ...) is what shuts us out. The owner has to grant it.
# Reporting both as "no permissions" sends the reader to check the role's
# permissions, which are fine, half the time.
RESOURCE_POLICY_RE = re.compile(r"because no resource-based policy allows")
OWN_PERMISSION_RE = re.compile(r"because no identity-based policy allows")

# The ARN of the resource that rejected the call, when the message carries
# one. It's who to ask for access.
RESOURCE_IN_ERROR_RE = re.compile(r"on resource:\s*[\"']?(arn:aws[^\s\"']+)")

# Generic denial: covers the cases where AWS didn't explain WHICH policy
# blocked it (most services don't add that phrase), so without either of the
# two phrases above the default is "ours," not "unknown": it's the most
# common reading and the most actionable one.
DENIAL_RE = re.compile(
    r"AccessDenied|AccessDeniedException|UnauthorizedOperation|"
    r"AuthFailure|NotAuthorized|Forbidden|InvalidClientTokenId|"
    r"SignatureDoesNotMatch|OptInRequired|SubscriptionRequiredException"
)

# The resource stopped existing BETWEEN c7n's enumeration call and its
# detail call (an instance that terminated, a volume that got deleted).
# It's not a coverage gap: there's nothing left to look at.
EPHEMERAL_RESOURCE_RE = re.compile(
    r"\b("
    r"InvalidInstanceID\.NotFound|InvalidInstanceId\.NotFound|"
    r"InvalidVolume\.NotFound|InvalidSnapshot\.NotFound|"
    r"InvalidAMIID\.NotFound|InvalidLaunchTemplateId\.NotFound|"
    r"NoSuchEntity|ResourceNotFoundException|"
    r"DBInstanceNotFound|DBSnapshotNotFound|ClusterNotFound"
    r")\b"
)

# Throttling: it needs a retry, it's not a coverage gap or a permissions
# problem. Covers AWS's generic throttling codes plus the specific case of
# "a resource AWS generates one at a time per account" (the IAM credential
# report is the real example: 5 policies requesting it at once cascade into
# ReportInProgress/LimitExceeded).
THROTTLED_RE = re.compile(
    r"\b("
    r"Throttling|ThrottlingException|TooManyRequestsException|"
    r"RequestLimitExceeded|SlowDown|ProvisionedThroughputExceededException|"
    r"ReportInProgress|ReportGenerationLimitExceeded|LimitExceeded"
    r")\b"
)

# "Could not connect to the endpoint." The text is IDENTICAL for a network
# outage and for a service AWS doesn't offer in that region: what tells them
# apart is consensus (see `_mark_service_absent`), not the line's text.
ENDPOINT_RE = re.compile(
    r"Could not connect to the endpoint URL:\s*\"?https?://([^/\"\s]+)"
)


@dataclass(frozen=True)
class Gap:
    """A coverage gap: something the run couldn't look at.

    `resource` is the ARN when the error names one (today that only happens
    for resource-policy, which is exactly where it matters most: it's who to
    ask for access). `raw` keeps the full log line so whoever investigates
    can go straight to the source without rerunning anything.
    """
    account: str
    region: str
    policy: str
    kind: str
    resource: Optional[str]
    raw: str


# Contract kinds. `UNKNOWN` is mandatory and visible: see the module and
# `classify` docstrings.
OWN_PERMISSION = "own-permission"
RESOURCE_POLICY = "resource-policy"
SERVICE_ABSENT = "service-absent"
EPHEMERAL_RESOURCE = "ephemeral-resource"
THROTTLED = "throttled"
UNKNOWN = "unknown"

DEFAULT_ACCOUNTS_FOR_CONSENSUS = 2


class _Candidate:
    """A gap halfway classified: gathers what could be parsed from ONE line.

    Exists because `service-absent` can't be decided line by line: it
    requires having seen the rest of the accounts first (see
    `_mark_service_absent`). Everything else could be resolved right there,
    but for consistency everything gets resolved together in `_final_kind`.
    """

    __slots__ = ("account", "region", "policy", "error", "raw")

    def __init__(self, account, region, policy, error, raw):
        self.account = account
        self.region = region
        self.policy = policy
        self.error = error or ""
        self.raw = raw


def _parse_line(line: str):
    """A `_Candidate`, or None if the line doesn't match any known format.

    A line that matches NONE of the three formats isn't a gap: it's normal
    log noise (progress, "Ran account:... matched:N", etc). That's different
    from a line that matches a format but whose error TEXT can't be
    classified: that one is still a gap, and it falls into `unknown` (see
    `classify`).
    """
    m = ACCESS_DENIED_RE.search(line)
    if m:
        d = m.groupdict()
        return _Candidate(d["account"], d["region"], d["policy"], None, line)

    m = POLICY_LOAD_ERROR_RE.search(line)
    if m:
        d = m.groupdict()
        return _Candidate(d["account"], d["region"], POLICY_UNIDENTIFIED,
                           d.get("error"), line)

    m = POLICY_ERROR_RE.search(line)
    if m:
        d = m.groupdict()
        return _Candidate(d["account"], d["region"], d["policy"],
                           d.get("error"), line)

    return None


def _mark_service_absent(candidates, accounts_for_consensus):
    """{(policy, region) that reached service-absent consensus}.

    The endpoint's DNS name is PER REGION and shared by every account: if it
    doesn't resolve, it doesn't resolve for anyone. A real network outage
    landing on exactly the same (policy, region) across several independent
    accounts in the same run is unlikely; a region missing the service hits
    every account, always. That's why consensus (not the line's text, which
    is identical in both cases) is what tells the two apart.

    `accounts_for_consensus` is the threshold: how many DISTINCT accounts
    have to fail identically on the same (policy, region) to conclude "it's
    the region." Configurable on purpose: with few accounts in the
    organization, 2 might be too high (never reached) or too low (a real
    2-account network-outage coincidence reads as a missing region). Whoever
    uses the kit knows their own account count.
    """
    by_key = {}
    for c in candidates:
        if ENDPOINT_RE.search(c.error):
            by_key.setdefault((c.policy, c.region), set()).add(c.account)
    return {key for key, accounts in by_key.items()
            if len(accounts) >= accounts_for_consensus}


def _final_kind(c: _Candidate, consensus) -> tuple[str, Optional[str]]:
    """(kind, resource) for a candidate with the global consensus already resolved.

    The order matters and is deliberate:
      1. service-absent first: if there's consensus, retrying changes
         nothing, so there's no point evaluating it as if it were a denial.
      2. resource-policy BEFORE the generic denial: the specific phrase is
         more informative than the generic code and should be preferred
         when present.
      3. ephemeral-resource and throttled are mutually exclusive with the
         above in practice (they're AWS codes distinct from AccessDenied),
         but they're listed in a fixed order in case some future service
         ever combines texts in the same message.
      4. own-permission is the default for "there was an AccessDenied" when
         AWS didn't say which of the two policies blocked it (most services
         don't add that phrase) or when there's no error text at all (the
         `ACCESS_DENIED_RE` case, which is a literal `AccessDenied`).
      5. if none of the above matched, `unknown`. Never dropped.
    """
    if (c.policy, c.region) in consensus and ENDPOINT_RE.search(c.error):
        return SERVICE_ABSENT, None

    m = RESOURCE_POLICY_RE.search(c.error)
    if m:
        m_arn = RESOURCE_IN_ERROR_RE.search(c.error)
        return RESOURCE_POLICY, (m_arn.group(1) if m_arn else None)

    if EPHEMERAL_RESOURCE_RE.search(c.error):
        return EPHEMERAL_RESOURCE, None

    if THROTTLED_RE.search(c.error):
        return THROTTLED, None

    # `error == ""` is the ACCESS_DENIED_RE case: no text, but the line
    # format itself is already a literal S3/IAM/STS AccessDenied.
    if not c.error or DENIAL_RE.search(c.error) or OWN_PERMISSION_RE.search(c.error):
        return OWN_PERMISSION, None

    return UNKNOWN, None


def classify(c7n_org_output: str,
             accounts_for_consensus: int = DEFAULT_ACCOUNTS_FOR_CONSENSUS
             ) -> list[Gap]:
    """The list of gaps in a c7n-org run, each with its kind.

    `c7n_org_output` is the raw stdout+stderr of the run (c7n-org logs
    everything to stderr; if your orchestrator merges both streams into one,
    like ours does, pass that text as is). Whatever doesn't match a known
    log format isn't a gap: it's normal noise (progress, "matched:N", etc).
    Whatever DOES match a format but whose error text can't be recognized is
    still a gap, and falls into `unknown`: the kit's rule is that an absence
    is never a zero, and that includes the absence of a classification.

    `accounts_for_consensus` governs when a "could not connect to the
    endpoint" error moves from `unknown` (not enough evidence that it's the
    region and not a one-off network outage) to `service-absent` (several
    accounts failed identically on the same policy+region at once). See
    `_mark_service_absent`.
    """
    candidates = []
    for line in c7n_org_output.splitlines():
        c = _parse_line(line)
        if c is not None:
            candidates.append(c)

    consensus = _mark_service_absent(candidates, accounts_for_consensus)

    gaps = []
    for c in candidates:
        kind, resource = _final_kind(c, consensus)
        gaps.append(Gap(account=c.account, region=c.region, policy=c.policy,
                         kind=kind, resource=resource, raw=c.raw))
    return gaps


# ────────────────────────────────────────────────────────────────── render

_ACTION_BY_KIND = {
    OWN_PERMISSION: "add the permission to the role that runs c7n",
    RESOURCE_POLICY: "ask the resource owner to add the policy",
    SERVICE_ABSENT: "scope the policy with region conditions, nothing to fix",
    EPHEMERAL_RESOURCE: "none, the resource no longer exists",
    THROTTLED: "none, it retries on its own",
    UNKNOWN: "investigate the raw message, it didn't match any known kind",
}


def render_human(gaps: list[Gap]) -> str:
    """Readable summary to paste into a message or a PR.

    Groups by kind and shows `unknown` FIRST and always, even if it's empty:
    it's the kind this kit exists to keep from slipping by silently, so it
    can't depend on the reader remembering to look for it further down a
    long list.
    """
    if not gaps:
        return "No gaps: the run didn't log a single failed invocation."

    by_kind: dict[str, list[Gap]] = {}
    for g in gaps:
        by_kind.setdefault(g.kind, []).append(g)

    lines = [f"{len(gaps)} coverage gap(s)."]

    unknowns = by_kind.get(UNKNOWN, [])
    if unknowns:
        lines.append("")
        lines.append(
            f"⚠ {len(unknowns)} unclassified (UNKNOWN): "
            f"{_ACTION_BY_KIND[UNKNOWN]}:")
        for g in unknowns:
            lines.append(f"  - {g.account}/{g.region} {g.policy}: {g.raw}")

    order = [OWN_PERMISSION, RESOURCE_POLICY, SERVICE_ABSENT,
             EPHEMERAL_RESOURCE, THROTTLED]
    for kind in order:
        items = by_kind.get(kind, [])
        if not items:
            continue
        lines.append("")
        lines.append(f"{kind} ({len(items)}): {_ACTION_BY_KIND[kind]}:")
        for g in items:
            extra = f" [{g.resource}]" if g.resource else ""
            lines.append(f"  - {g.account}/{g.region} {g.policy}{extra}")

    return "\n".join(lines)


def _escape(value: str) -> str:
    """`value` in quotes, with internal quotes escaped.

    Generic `key="value"` format: what a SIEM (Splunk included) parses
    without extra configuration. Without this, a `raw` field with quotes or
    spaces would cut the field in half and the rest of the line would read
    as loose text, not fields.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_machine(gaps: list[Gap]) -> str:
    """One `key=value` line per gap, meant for a SIEM.

    Not grouped or summarized: each Gap is an independent, complete line,
    because the consumer (a log indexer) expects events, not a report.
    """
    lines = []
    for g in gaps:
        fields = [
            f"kind={g.kind}",
            f"account={g.account}",
            f"region={g.region}",
            f"policy={_escape(g.policy)}",
            f"resource={_escape(g.resource) if g.resource else '-'}",
            f"raw={_escape(g.raw)}",
        ]
        lines.append("gap " + " ".join(fields))
    return "\n".join(lines)
