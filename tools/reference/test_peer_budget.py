"""Exercise peer-budget admission without launching a service."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import peer_budget


class PeerBudgetTests(unittest.TestCase):
    def test_membership_requires_a_dedicated_service(self):
        self.assertEqual(
            peer_budget.peer_unit("0::/user.slice/gnunet-reference-check.service\n"),
            Path("user.slice/gnunet-reference-check.service"),
        )
        for membership in ("0::/\n", "0::/user.slice\n",
                           "0::/../gnunet-reference-check.service\n", "1:cpu:/test\n"):
            with self.subTest(membership=membership):
                with self.assertRaises(peer_budget.MissingPeerBudget):
                    peer_budget.peer_unit(membership)

    def test_effective_limits_must_all_be_available_and_bounded(self):
        with (TemporaryDirectory() as directory,
              patch.object(peer_budget.sys, "platform", "linux"),
              patch.object(peer_budget, "require_service_policy") as policy):
            root = Path(directory)
            group = root / "gnunet-reference-check.service"
            group.mkdir()
            proc = root / "membership"
            proc.write_text(f"0::/{group.name}\n")
            limits = {
                "cpu.max": "200000 100000",
                "memory.max": str(2 << 30),
                "memory.swap.max": "0",
                "pids.max": "128",
            }
            for key, value in limits.items():
                (group / key).write_text(value)
            peer_budget.require_peer_budget(proc, root)
            policy.assert_called_once_with(group.name)

            for key, invalid in (
                ("cpu.max", "max 100000"),
                ("cpu.max", "200001 100000"),
                ("memory.max", str((2 << 30) + 1)),
                ("memory.swap.max", "1"),
                ("pids.max", "129"),
                ("pids.max", "max"),
            ):
                with self.subTest(key=key, invalid=invalid):
                    (group / key).write_text(invalid)
                    with self.assertRaises(peer_budget.MissingPeerBudget):
                        peer_budget.require_peer_budget(proc, root)
                    (group / key).write_text(limits[key])
            (group / "pids.max").unlink()
            with self.assertRaises(peer_budget.MissingPeerBudget):
                peer_budget.require_peer_budget(proc, root)

    def test_native_macos_never_admits_the_topology(self):
        with patch.object(peer_budget.sys, "platform", "darwin"):
            with self.assertRaisesRegex(peer_budget.MissingPeerBudget, "disposable Linux guest"):
                peer_budget.require_peer_budget()

    def test_service_requires_external_lifetime_and_group_cleanup(self):
        good = (
            f't 260000000\nt 8000000\nu {os.getpid()}\nt 0\ns "no"\n'
            's "terminate"\ns "main"\ns "control-group"\nb true\n'
            's "exec"\nb false\n'
            'a(sasbttttuii) 0\na(sasbttttuii) 0\na(sasbttttuii) 0\n'
        )
        with patch.object(peer_budget.subprocess, "check_output", return_value=good) as query:
            peer_budget.require_service_policy("gnunet-reference-test.service")
            self.assertIn("/org/freedesktop/systemd1/unit/gnunet_2dreference_2dtest_2eservice",
                          query.call_args.args[0])
            for invalid in (
                good.replace("260000000", "18446744073709551615"),
                good.replace("8000000", "9000000"),
                good.replace(f"u {os.getpid()}", "u 0"),
                good.replace("t 0\n", "t 1\n"),
                good.replace('"no"', '"always"'),
                good.replace('"terminate"', '"abort"'),
                good.replace('"main"', '"cgroup"'),
                good.replace('"control-group"', '"process"'),
                good.replace("b true", "b false"),
                good.replace('s "exec"', 's "oneshot"'),
                good.replace("b false", "b true"),
                good.replace("a(sasbttttuii) 0", "a(sasbttttuii) 1 entry", 1),
            ):
                with self.subTest(invalid=invalid):
                    query.return_value = invalid
                    with self.assertRaises(peer_budget.MissingPeerBudget):
                        peer_budget.require_service_policy("gnunet-reference-test.service")


if __name__ == "__main__":
    unittest.main()
