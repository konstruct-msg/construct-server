#!/usr/bin/env python3
"""Does the monitoring actually monitor anything?

Three times now the answer has been no, and each time everything looked fine:

  * alerts.yml was mounted but `rule_files` was unset — no rule had ever run;
  * the Redis exporter ran but was in no scrape_config — the memory alerts could
    not have fired even once;
  * ops/prometheus/prometheus.yml was edited to add node/postgres scrapes while
    docker-compose mounts ops/prometheus.yml — the repo said one thing, the
    running process another.

Every one of those failures is silent in exactly the same way: a rule with no
data is `inactive`, which on the /alerts page is indistinguishable from healthy.
So a green dashboard proves nothing, and this script exists to prove the rest.

  python3 scripts/check-observability.py                 # static checks only
  python3 scripts/check-observability.py --live          # + ask Prometheus
  python3 scripts/check-observability.py --live --prometheus http://127.0.0.1:9090

Run `--live` on the server, or through the SSH tunnel described in construct-docs
manuals&instructions/Grafana_Prometheus_Access.md.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / "ops"

# PromQL words that tokenize like a metric but are not one.
PROMQL_RESERVED = {
    "and", "or", "unless", "by", "without", "on", "ignoring", "group_left",
    "group_right", "offset", "bool", "start", "end", "atan2", "inf", "nan",
    # Aggregation operators. Dropping "identifier immediately followed by (" is
    # not enough for these: `count without (cpu, mode) (…)` puts a modifier
    # between the name and its parenthesis, so `count` read as a metric name and
    # would have been reported as a series that does not exist.
    "sum", "min", "max", "avg", "group", "stddev", "stdvar", "count",
    "count_values", "topk", "bottomk", "quantile", "limitk", "limit_ratio",
}


def fail(msg: str) -> None:
    print(f"FAIL {msg}")


# ── static ──────────────────────────────────────────────────────────────────


def compose_mounts() -> dict[str, Path]:
    """host path -> container path, for every compose file under ops/.

    Parsed with regex rather than yaml so the script keeps working on a machine
    with no PyYAML; volume lines are `- ./x:/etc/y:ro` and nothing subtler.
    """
    mounts: dict[str, Path] = {}
    for compose in OPS.glob("docker-compose*.yml"):
        text = compose.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*-\s+(\./[^\s:]+):([^\s:]+)(?::\w+)?\s*$", text, re.M):
            host = (OPS / m.group(1)[2:]).resolve()
            mounts[str(host)] = compose
    return mounts


def is_mounted(path: Path, mounted: dict[str, Path]) -> bool:
    """A file counts as mounted if it, or any directory above it, is a source."""
    for p in [path, *path.parents]:
        if str(p) in mounted:
            return True
    return False


def check_no_orphan_configs() -> bool:
    """A config copy that nothing mounts is worse than no copy at all.

    It is where the next person edits, and the edit takes effect nowhere. This is
    what happened on 2026-08-12: the alerting fix landed in a file the container
    had never seen, and production kept the old scrape list for a day.
    """
    ok = True
    mounted = compose_mounts()
    names = ("prometheus.yml", "alerts.yml", "alertmanager.yml")
    for path in OPS.rglob("*.yml"):
        if path.name not in names:
            continue
        if not is_mounted(path.resolve(), mounted):
            ok = False
            fail(f"{path.relative_to(ROOT)} is mounted by no compose file — "
                 f"editing it changes nothing that runs. Delete it, or mount it.")
    return ok


def check_file_mounts() -> None:
    """Single-file bind mounts do not survive the deploy. Reported, not enforced.

    `docker run -v ./x.yml:/etc/x.yml` binds an inode. The deploy runs
    `git reset --hard`, which REPLACES files rather than rewriting them, so the
    container keeps serving the content it started with — no error, no warning,
    and `docker logs` even says the config was reloaded. Verified on 2026-08-13:
    host and container disagreed on the sha256 of prometheus.yml minutes after a
    successful SIGHUP reload.

    Prometheus and Alertmanager now mount their directories. Caddy still mounts
    a file, and restructuring the public TLS terminator is not something to do
    inside an unrelated change — so this warns, loudly, rather than failing. Until
    it is moved, a Caddyfile change needs `docker compose up -d --force-recreate
    caddy` by hand; it does NOT take effect on deploy.
    """
    for host, compose in sorted(compose_mounts().items()):
        p = Path(host)
        if p.is_file():
            print(f"  WARN {compose.name}: {p.relative_to(ROOT)} is a single-FILE "
                  f"bind mount — `git reset --hard` on deploy will not reach the "
                  f"container. Mount its directory, or force-recreate by hand.")


def check_grafana_provisioning() -> bool:
    """The dashboard provider's path must be a directory the compose file mounts.

    provisioning/dashboards/construct.yaml pointed at /etc/grafana/dashboards
    while the mount put the files in /var/lib/grafana/dashboards. Grafana starts
    happily, logs nothing alarming, and provisions an empty directory: you get a
    working Grafana with no dashboards and no reason given. Third instance today
    of one config naming a path another config does not provide.

    Also checks every panel's datasource uid against the provisioned datasource —
    a dashboard exported from a different Grafana carries that instance's uid and
    renders "Datasource not found" on every panel.
    """
    ok = True
    mounts = {}  # container destination -> host source
    for compose in OPS.glob("docker-compose*.yml"):
        for m in re.finditer(r"^\s*-\s+(\./[^\s:]+):([^\s:]+)(?::\w+)?\s*$",
                             compose.read_text(encoding="utf-8"), re.M):
            mounts[m.group(2)] = (OPS / m.group(1)[2:]).resolve()

    prov = OPS / "grafana/provisioning/dashboards/construct.yaml"
    if prov.exists():
        for m in re.finditer(r"^\s*path:\s*(\S+)", prov.read_text(encoding="utf-8"), re.M):
            want = m.group(1)
            if want not in mounts:
                ok = False
                fail(f"grafana dashboard provider reads {want}, which no compose "
                     f"file mounts — Grafana will provision an empty directory. "
                     f"Mounted: {', '.join(sorted(k for k in mounts if 'grafana' in k))}")

    uids = set()
    ds_dir = OPS / "grafana/provisioning/datasources"
    for f in ds_dir.glob("*.y*ml") if ds_dir.exists() else []:
        uids |= set(re.findall(r"^\s*uid:\s*(\S+)", f.read_text(encoding="utf-8"), re.M))
    for dash in (OPS / "grafana/dashboards").glob("*.json"):
        used = set(re.findall(r'"uid":\s*"([^"]+)"', dash.read_text(encoding="utf-8")))
        for uid in sorted(used - uids - {dash.stem}):
            if uid.startswith("construct-overview"):   # the dashboard's own uid
                continue
            ok = False
            fail(f"{dash.name} references datasource uid \"{uid}\", which is not "
                 f"provisioned ({', '.join(sorted(uids)) or 'none'}) — every panel "
                 f"will render 'Datasource not found'.")
    return ok


def check_metrics_have_producers() -> bool:
    """A metric declared and never written is a panel that can never fill.

    Sixteen of the 38 metrics in construct-metrics had no producer anywhere in
    the workspace on 2026-08-13, and the Grafana overview was built on them: five
    session panels, OTPK inventory, active gRPC streams, KT proofs, all three
    gateway request panels. Nineteen of 27 panels read "No data" — which looks
    exactly like an outage and had to be investigated to find out it was not.

    The inverse of the rule in AGENTS.md about a producer with no consumer, and
    it rots the same way: nothing breaks, the declaration just stops meaning
    anything.

    A ratchet rather than a threshold. The existing sixteen are listed in
    scripts/.metrics-without-producer with a reason; the count can only go down.
    Adding a new unwritten metric fails, and so does leaving a name on the list
    after it gains a producer — a stale exemption is how a list like this becomes
    decoration.
    """
    import subprocess
    lib = ROOT / "crates/construct-metrics/src/lib.rs"
    if not lib.exists():
        return True
    src = lib.read_text(encoding="utf-8")
    declared = re.findall(r'pub static (\w+):[\s\S]{0,400}?"((?:construct|gateway)_[a-z_0-9]+)"', src)

    # A metric is produced if its static is named outside the metrics crate, or
    # if a helper inside the crate writes it and that helper is called outside.
    # {STATIC_NAME: helper_fn} — a metric written only through a wrapper is still
    # produced. Getting this mapping backwards reported the two fail-open
    # counters as orphans, and they are the ones with the most callers.
    helpers: dict[str, str] = {}
    for m in re.finditer(r"pub fn (\w+)\([^)]*\)\s*\{\s*(\w+)\s*\n?\s*\.", src):
        helpers.setdefault(m.group(2), m.group(1))
    unproduced = []
    for static, metric in declared:
        names = [static] + ([helpers[static]] if static in helpers else [])
        produced = False
        for name in names:
            out = subprocess.run(["git", "grep", "-l", "-w", name, "--", "*.rs"],
                                 cwd=ROOT, capture_output=True, text=True).stdout.split()
            if any("construct-metrics" not in f for f in out):
                produced = True
                break
        if not produced:
            unproduced.append(metric)

    allow_file = ROOT / "scripts/.metrics-without-producer"
    allowed = set()
    if allow_file.exists():
        allowed = {l.split("#")[0].strip() for l in
                   allow_file.read_text(encoding="utf-8").splitlines()
                   if l.split("#")[0].strip()}

    ok = True
    for metric in sorted(set(unproduced) - allowed):
        ok = False
        fail(f"{metric} is declared in construct-metrics and written nowhere — a "
             f"panel or alert reading it can never fill. Instrument it, delete it, "
             f"or add it to scripts/.metrics-without-producer with a reason.")
    declared_names = {metric for _, metric in declared}
    for metric in sorted(allowed - set(unproduced)):
        ok = False
        if metric not in declared_names:
            fail(f"{metric} is listed in scripts/.metrics-without-producer but is no "
                 f"longer declared at all — delete the line.")
        else:
            fail(f"{metric} is listed in scripts/.metrics-without-producer but now HAS "
                 f"a producer — remove the line, or the list stops meaning anything.")
    if unproduced:
        print(f"  note: {len(unproduced)} metric(s) declared with no producer "
              f"(known, see scripts/.metrics-without-producer)")
    return ok


def check_mount_sources_exist() -> bool:
    """Docker creates a *directory* for a missing bind-mount source.

    Prometheus then dies with "is a directory", which reads like an image problem
    rather than a typo in a path. Cheaper to catch here.

    Secrets are the exception: ops/alertmanager/telegram_token is gitignored and
    is *supposed* to be absent from a checkout. Failing on it would make this
    script permanently red on every laptop, and a check that is always red is a
    check nobody reads — so it warns here and fails on the server, where the file
    genuinely must exist before the container starts.
    """
    ok = True
    for host, compose in sorted(compose_mounts().items()):
        p = Path(host)
        if p.exists():
            continue
        rel = p.relative_to(ROOT)
        if ignored(p):
            print(f"  note: {rel} is absent (gitignored secret) — "
                  f"{compose.name} will not start until it is created on the server")
            continue
        ok = False
        fail(f"{compose.name} mounts {rel} which does not exist — "
             f"Docker will silently create a directory there.")
    return ok


def ignored(path: Path) -> bool:
    import subprocess
    return subprocess.run(["git", "check-ignore", "-q", str(path)],
                          cwd=ROOT, capture_output=True).returncode == 0


def metrics_in(expr: str) -> set[str]:
    expr = re.sub(r"\{[^}]*\}", "", expr)          # label selectors
    expr = re.sub(r"\[[^\]]*\]", "", expr)         # ranges
    expr = re.sub(r'"[^"]*"', "", expr)            # strings
    # Grouping lists: the contents are label names, not metrics.
    expr = re.sub(r"\b(?:by|without|on|ignoring)\s*\([^)]*\)", " ", expr)
    found = set()
    for m in re.finditer(r"[a-zA-Z_:][a-zA-Z0-9_:]*", expr):
        name = m.group(0)
        if name in PROMQL_RESERVED:
            continue
        if expr[m.end():m.end() + 1] == "(":       # function call
            continue
        found.add(name)
    return found


def rules_and_metrics() -> list[tuple[str, str, set[str]]]:
    """(group, alert, metrics) for every rule, without a YAML dependency."""
    text = (OPS / "prometheus/alerts.yml").read_text(encoding="utf-8")
    out: list[tuple[str, str, set[str]]] = []
    group = "?"
    for block in re.finditer(
            r"^\s*- name:\s*(\S+)|^\s*- alert:\s*(\S+)\s*\n\s*expr:\s*(>?-?)\s*\n?((?:.|\n)*?)(?=\n\s*(?:for|labels|annotations):)",
            text, re.M):
        if block.group(1):
            group = block.group(1)
            continue
        alert, expr = block.group(2), block.group(4)
        out.append((group, alert, metrics_in(expr)))
    return out


# ── live ────────────────────────────────────────────────────────────────────


def declared_in_source(metric: str) -> bool:
    """Is this metric name written anywhere in the Rust workspace?

    Exporters (node_*, pg_*, redis_*) are not, and must therefore be scraped to
    exist at all — for them, absent series is always a finding.
    """
    import subprocess
    r = subprocess.run(["git", "grep", "-q", "-F", metric, "--", "*.rs"],
                       cwd=ROOT, capture_output=True)
    return r.returncode == 0


def api(base: str, path: str, **params) -> dict:
    url = f"{base}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def check_live(base: str) -> bool:
    ok = True

    targets = api(base, "/api/v1/targets", state="any")["data"]["activeTargets"]
    down = [t for t in targets if t["health"] != "up"]
    print(f"  targets: {len(targets)} configured, {len(down)} not up")
    for t in down:
        ok = False
        fail(f"target {t['labels'].get('job')} ({t['scrapeUrl']}) is "
             f"{t['health']}: {t.get('lastError', '')[:80]}")

    # Every rule in the repo must exist in the running Prometheus. If a group is
    # missing, the file being loaded is not this file.
    loaded = {r["name"]
              for g in api(base, "/api/v1/rules")["data"]["groups"]
              for r in g["rules"]}
    declared = {alert for _, alert, _ in rules_and_metrics()}
    for alert in sorted(declared - loaded):
        ok = False
        fail(f"rule {alert} is in ops/prometheus/alerts.yml but not loaded by the running "
             f"Prometheus — it is evaluating a different file.")

    # The point of the whole exercise: a rule whose metrics have no series is
    # permanently green and says nothing. This is the check that would have
    # caught all three historical failures on the day they happened.
    for group, alert, metrics in rules_and_metrics():
        for metric in sorted(metrics):
            res = api(base, "/api/v1/query", query=f"count({metric})")
            if res["data"]["result"]:
                continue
            # "No series" has two very different causes and only one is a defect.
            # A labelled counter is registered on its FIRST increment, so a
            # counter for something that has never happened is legitimately
            # absent — construct_msg_abuse_fail_open_total means the sentinel
            # limiter has never degraded, which is the outcome we want. Failing
            # on that would train everyone to ignore this output.
            #
            # The distinguishing question is whether anything can ever produce
            # it. If the name appears in the source, the wiring exists and we are
            # waiting for the event; if it appears nowhere, the rule is reading a
            # metric that does not exist — a typo, a rename, or an exporter that
            # was never scraped, which is exactly the class this script is for.
            if declared_in_source(metric):
                print(f"  note: {group}/{alert} reads `{metric}` — declared in the "
                      f"source but never yet incremented. Expected while the "
                      f"condition it counts has not occurred.")
                continue
            ok = False
            fail(f"{group}/{alert} reads `{metric}`, which has no series and "
                 f"appears in no source file — the rule cannot fire. Is its "
                 f"exporter scraped, or is the name wrong?")

    ams = api(base, "/api/v1/alertmanagers")["data"]["activeAlertmanagers"]
    if not ams:
        ok = False
        fail("no Alertmanager is connected — rules evaluate, and then nobody is "
             "told. Start ops/docker-compose.observability.yml.")
    else:
        print(f"  alertmanagers: {', '.join(a['url'] for a in ams)}")

    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--prometheus", default="http://127.0.0.1:9090")
    args = ap.parse_args()

    # Not `and` — that short-circuits, and a second finding hidden behind the
    # first is how a two-line fix turns into two round trips.
    ok = check_no_orphan_configs()
    ok = check_mount_sources_exist() and ok
    ok = check_grafana_provisioning() and ok
    ok = check_metrics_have_producers() and ok
    check_file_mounts()

    rules = rules_and_metrics()
    if not rules:
        # A self-test, because an extractor that silently finds nothing would
        # make every check below pass. Same trap the mutation harness fell into.
        fail("parsed 0 rules out of ops/prometheus/alerts.yml — the extractor is broken, "
             "not the config.")
        return 1
    print(f"  {len(rules)} alert rule(s) parsed, "
          f"{len({m for _, _, ms in rules for m in ms})} distinct metric(s) referenced")

    if args.live:
        try:
            ok = check_live(args.prometheus) and ok
        except urllib.error.URLError as e:
            fail(f"cannot reach Prometheus at {args.prometheus}: {e}. Run this on "
                 f"the server, or open the tunnel first.")
            return 2

    if ok:
        print("OK: monitoring is wired to something real.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
