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
            if not res["data"]["result"]:
                ok = False
                fail(f"{group}/{alert} reads `{metric}`, which has no series — "
                     f"the rule cannot fire. Is its exporter scraped?")

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
