#!/usr/bin/env python3
"""Pure/fake-Docker contracts; never connect to a host or read real credentials."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("window", Path(__file__).with_name("messaging-test-limit-window.py"))
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


def container(image="current-image", cap="30"):
    return {"Config": {"Image": image, "Env": ["PATH=/bin", "TEST_SECRET=not-a-real-secret", w.CAP_KEY+"="+cap]},
            "Image": "current-image-id", "State": {"Running": True}}


class WindowTests(unittest.TestCase):
    def test_override_preserves_current_image_and_only_changes_cap(self):
        current = container(image="a-new-deployment-not-the-old-test-image")
        self.assertEqual(w.override_for(current, 30), {"services": {"messaging": {
            "image": current["Config"]["Image"], "environment": {w.CAP_KEY: "30"}}}})

    def test_fingerprint_excludes_only_cap_not_credentials(self):
        old = {"secret": "dummy-one", w.CAP_KEY: "30"}
        self.assertEqual(w.fingerprint(old), w.fingerprint({**old, w.CAP_KEY: "1200"}))
        self.assertNotEqual(w.fingerprint(old), w.fingerprint({**old, "secret": "dummy-two"}))

    def test_timer_survives_host_reboot_and_retries_docker_failure(self):
        deadline = dt.datetime(2026, 11, 12, 16, 0, 0, tzinfo=dt.timezone.utc)
        service, timer = w.window_units(Path("/var/lib/construct-loadtest/run-123456abcdef/control.py"), deadline, "test-unit")
        self.assertIn("OnCalendar=2026-11-12 16:00:00 UTC", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("Restart=on-failure", service)
        self.assertIn("After=docker.service", service)
        self.assertIn("ExecStart=/usr/bin/python3 /var/lib/construct-loadtest/run-123456abcdef/control.py restore", service)
        self.assertNotIn("--on-active", timer)

    def test_invalid_or_unacknowledged_windows_never_inspect_docker(self):
        with patch.object(w, "inspect_container") as inspect:
            for cap, minutes, ack in [(0, 10, True), (30, 10, True), (1201, 10, True), (100, 0, True), (100, 16, True), (100, 10, False)]:
                with self.assertRaises(ValueError):
                    w.arm(Path("/not-written"), cap, minutes, ack)
            inspect.assert_not_called()

    def test_changed_secret_in_compose_dry_render_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            current = container()
            rendered = {"services": {"messaging": {"image": "current-image", "environment": {
                "TEST_SECRET": "different-dummy-secret", w.CAP_KEY: "1200"}}}}
            baked = [{"Config": {"Env": ["PATH=/bin"]}}]
            with patch.object(w, "compose_command", return_value=["fake-compose"]), patch.object(w, "run", side_effect=[json.dumps(rendered), json.dumps(baked)]):
                with self.assertRaisesRegex(ValueError, "another environment value"):
                    w.prepared_command(current, directory, 1200)

    def test_partial_apply_calls_restore_and_arms_timer_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "run-123456abcdef"
            directory.mkdir()
            calls = []
            def command(args):
                calls.append(args)
                return "active\n" if "is-active" in args else ""
            def recreate(*args):
                self.assertTrue(any("is-active" in call for call in calls))
                self.assertTrue((directory / "state.json").exists())
                raise RuntimeError("simulated partial recreate")
            with patch.object(w, "UNIT_ROOT", Path(tmp)), patch.object(w, "inspect_container", return_value=container()), patch.object(w, "prepared_command", return_value=[]), patch.object(w, "run", side_effect=command), patch.object(w, "recreate", side_effect=recreate), patch.object(w, "restore") as restore:
                with self.assertRaisesRegex(RuntimeError, "partial recreate"):
                    w.arm(directory, 1200, 15, True)
                restore.assert_called_once_with(directory)

    def test_inactive_rollback_timer_prevents_cap_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "run-123456abcdef"
            directory.mkdir()
            with patch.object(w, "UNIT_ROOT", Path(tmp)), patch.object(w, "inspect_container", return_value=container()), patch.object(w, "prepared_command", return_value=[]), patch.object(w, "run", return_value="inactive\n"), patch.object(w, "recreate") as recreate:
                with self.assertRaisesRegex(RuntimeError, "rollback timer not active"):
                    w.arm(directory, 1200, 15, True)
                recreate.assert_not_called()

    def test_restore_uses_current_deployment_and_does_not_touch_another_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "run-123456abcdef"
            directory.mkdir()
            w.write_json(directory / "state.json", {"status": "armed", "unit": "test-unit", "original_cap": 30})
            w.write_json(Path(tmp) / "active.json", {"directory": str(directory)})
            current = container(image="new-image", cap="1200")
            with patch.object(w, "inspect_container", return_value=current), patch.object(w, "prepared_command", return_value=["planned"]) as plan, patch.object(w, "recreate") as recreate, patch.object(w, "run"), contextlib.redirect_stdout(io.StringIO()):
                w.restore(directory)
                plan.assert_called_once_with(current, directory, 30)
                recreate.assert_called_once_with(current, ["planned"], 30)
                self.assertFalse((Path(tmp) / "active.json").exists())
                self.assertEqual(json.loads((directory / "state.json").read_text())["status"], "restored")
                # An old completed window may be invoked again while a new window is active.
                w.write_json(Path(tmp) / "active.json", {"directory": "another-window"})
                w.restore(directory)
                self.assertEqual(recreate.call_count, 1)
                self.assertTrue((Path(tmp) / "active.json").exists())

    def test_active_foreign_lease_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "run-123456abcdef"
            directory.mkdir()
            w.write_json(Path(tmp) / "active.json", {"directory": "another-window"})
            with self.assertRaises(ValueError), patch.object(w, "inspect_container") as inspect:
                w.arm(directory, 1200, 15, True)
            inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
