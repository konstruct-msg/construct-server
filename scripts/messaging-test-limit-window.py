#!/usr/bin/env python3
"""Bounded test-only messaging IP cap; durable systemd rollback, no app.env edits.

Run ON the Docker host. JSON is operator configuration/state, never message payload.
The override pins the running image; restore preserves whichever image is then running.
No credentials/config render are printed or persisted. Production caps are not sized here.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess

CAP_KEY = "MSG_SEALED_IP_RATE_LIMIT_PER_MIN"
DEFAULT_CAP = 30
CONTAINER = "construct-messaging-1"
WINDOW_ROOT = Path("/var/lib/construct-loadtest")
UNIT_ROOT = Path("/etc/systemd/system")


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode:
        # Never echo rendered compose config, environment or arbitrary stderr.
        raise RuntimeError(f"command failed ({result.returncode}): {args[0:2]}")
    return result.stdout


def inspect_container():
    return json.loads(run(["docker", "inspect", CONTAINER]))[0]


def environment(items):
    return dict(item.split("=", 1) for item in (items or []))


def fingerprint(env):
    return hashlib.sha256(json.dumps(sorted((k, v) for k, v in env.items() if k != CAP_KEY)).encode()).hexdigest()


def old_cap(current):
    value = environment(current["Config"]["Env"]).get(CAP_KEY, str(DEFAULT_CAP))
    cap = int(value)
    if not 1 <= cap <= 2**32 - 1:
        raise ValueError("existing cap is invalid")
    return cap


def override_for(current, cap):
    # Restore MUST use current image, not the image recorded when a test began.
    return {"services": {"messaging": {"image": current["Config"]["Image"],
                                      "environment": {CAP_KEY: str(cap)}}}}


def compose_command(current, directory, override):
    labels = current["Config"]["Labels"]
    if labels["com.docker.compose.service"] != "messaging":
        raise ValueError("unexpected service")
    files = labels["com.docker.compose.project.config_files"].split(",")
    # Remove only overrides owned by THIS window, including a previous restore override.
    files = [p for p in files if Path(p).parent.resolve() != directory.resolve()]
    if not files or not all(Path(p).is_absolute() and Path(p).is_file() for p in files):
        raise ValueError("baseline compose files are missing")
    command = ["docker", "compose", "-p", labels["com.docker.compose.project"],
               "--project-directory", labels["com.docker.compose.project.working_dir"]]
    env_file = labels.get("com.docker.compose.project.environment_file")
    if not env_file or not Path(env_file).is_file():
        raise ValueError("explicit baseline compose environment file is required")
    command += ["--env-file", env_file]
    for file in files + [str(override)]:
        command += ["-f", file]
    return command


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def prepared_command(current, directory, cap):
    override = directory / "limit.override.json"
    write_json(override, override_for(current, cap))
    command = compose_command(current, directory, override)
    rendered = json.loads(run(command + ["config", "--format", "json"]))
    service = rendered["services"]["messaging"]
    if service["image"] != current["Config"]["Image"]:
        raise ValueError("image would change")
    baked = json.loads(run(["docker", "image", "inspect", current["Image"]]))[0]
    planned = environment(baked["Config"].get("Env"))
    for key, value in service.get("environment", {}).items():
        if value is None:
            planned.pop(key, None)
        else:
            planned[key] = str(value)
    if fingerprint(planned) != fingerprint(environment(current["Config"]["Env"])):
        raise ValueError("compose would change another environment value; aborting")
    return command


def recreate(current, command, cap):
    run(command + ["up", "-d", "--no-deps", "--no-build", "--pull", "never", "--force-recreate", "messaging"])
    after = inspect_container()
    if not after["State"]["Running"] or after["Image"] != current["Image"]:
        raise RuntimeError("running image verification failed")
    actual = environment(after["Config"]["Env"])
    if actual.get(CAP_KEY) != str(cap):
        raise RuntimeError("cap verification failed")
    if fingerprint(actual) != fingerprint(environment(current["Config"]["Env"])):
        raise RuntimeError("another environment value changed")


def window_units(script, deadline, unit):
    service = ("[Unit]\nDescription=Restore bounded messaging test IP limit\n"
               "After=docker.service\nRequires=docker.service\nStartLimitIntervalSec=0\n"
               "[Service]\nType=oneshot\n"
               f"ExecStart=/usr/bin/python3 {script} restore\n"
               "Restart=on-failure\nRestartSec=15s\n")
    timer = ("[Unit]\nDescription=Bounded messaging test IP limit deadline\n[Timer]\n"
             f"OnCalendar={deadline.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
             f"Unit={unit}.service\nPersistent=true\nAccuracySec=1s\n"
             "[Install]\nWantedBy=timers.target\n")
    return service, timer


def restore(directory):
    path = directory / "state.json"
    state = json.loads(path.read_text())
    already = state["status"] == "restored"
    lease = directory.parent / "active.json"
    owns_lease = lease.exists() and json.loads(lease.read_text())["directory"] == str(directory)
    if not already and lease.exists() and not owns_lease:
        raise RuntimeError("another window owns the lease; refusing to change its cap")
    if state["status"] != "restored":
        current = inspect_container()
        cap = state["original_cap"]
        # Normal redeploy may already have removed the override. Do not recreate needlessly.
        if environment(current["Config"]["Env"]).get(CAP_KEY) != str(cap) or not current["State"]["Running"]:
            command = prepared_command(current, directory, cap)
            recreate(current, command, cap)
        state["status"] = "restored"
        write_json(path, state)
    run(["systemctl", "disable", "--now", state["unit"] + ".timer"])
    if owns_lease:
        lease.unlink(missing_ok=True)
    print(json.dumps({"status": "already-restored"} if already else
                     {"status": "restored", "effective_cap": state["original_cap"]}))


def arm(directory, cap, minutes, acknowledge):
    if not acknowledge or not 31 <= cap <= 1200 or not 1 <= minutes <= 15:
        raise ValueError("explicit reconnect acknowledgement, cap 31..1200 and window 1..15 minutes required")
    if (directory / "state.json").exists() or (directory.parent / "active.json").exists():
        raise ValueError("window already initialized or another window is active")
    # A durable named unit, not a transient --on-active timer that vanishes on host reboot.
    deadline = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)
    unit = "construct-load-" + directory.name
    current = inspect_container()
    command = prepared_command(current, directory, cap)  # dry-run BEFORE arming/mutation
    service, timer = window_units(directory / Path(__file__).name, deadline, unit)
    state = {"status": "armed", "original_cap": old_cap(current), "cap": cap,
             "deadline": deadline.isoformat(), "unit": unit}
    write_json(directory / "state.json", state)
    write_json(directory.parent / "active.json", {"directory": str(directory)})
    for suffix, content in [("service", service), ("timer", timer)]:
        target = UNIT_ROOT / (unit + "." + suffix)
        with open(target, "x", encoding="utf-8") as stream:
            stream.write(content)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", unit + ".timer"])
    if run(["systemctl", "is-active", unit + ".timer"]).strip() != "active":
        raise RuntimeError("rollback timer not active; refusing to change cap")
    try:
        recreate(current, command, cap)
    except Exception:
        # A partial compose recreation also needs rollback. Persistent timer remains armed
        # if Docker is unavailable and this immediate restore fails.
        restore(directory)
        raise
    print(json.dumps({"status": "active", "effective_cap": cap, "deadline": state["deadline"], "unit": unit}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["plan", "arm", "restore"])
    parser.add_argument("--cap", type=int, default=0)
    parser.add_argument("--minutes", type=int, default=0)
    parser.add_argument("--acknowledge-reconnect", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("run on the Docker host as root")
    directory = Path(__file__).resolve().parent
    if directory.parent != WINDOW_ROOT or not re.fullmatch(r"run-[a-f0-9]{12}", directory.name):
        raise PermissionError("install in /var/lib/construct-loadtest/run-<12 hex digits>")
    if any(path.stat().st_uid != 0 or path.stat().st_mode & 0o077
           for path in [directory, WINDOW_ROOT]):
        raise PermissionError("window and parent must be root-owned/private (0700)")
    os.umask(0o077)
    # The deadline restore waits for any in-flight apply, then runs immediately; a slow
    # recreate cannot finish AFTER a simultaneous restore and leave the high cap behind.
    with open(WINDOW_ROOT / "window.lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.mode == "restore":
            restore(directory)
        elif args.mode == "plan":
            if not 31 <= args.cap <= 1200 or (directory / "state.json").exists():
                raise ValueError("plan requires cap 31..1200 and a fresh window directory")
            current = inspect_container()
            prepared_command(current, directory, args.cap)
            print(json.dumps({"status": "plan-only", "original_cap": old_cap(current),
                              "test_cap": args.cap, "image": current["Config"]["Image"],
                              "other_environment_unchanged": True}))
        else:
            arm(directory, args.cap, args.minutes, args.acknowledge_reconnect)


if __name__ == "__main__":
    main()
