"""scripts/housekeeping.py: saved benchmark runs never accumulate."""

import importlib.util
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

spec = importlib.util.spec_from_file_location("housekeeping", Path(settings.BASE_DIR, "scripts", "housekeeping.py"))
housekeeping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(housekeeping)


class PruneBenchmarksTest(SimpleTestCase):
    def test_keeps_the_newest_runs_per_machine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for machine, count in (("Linux-CPython-3.12-64bit", 7), ("Darwin-CPython-3.11-64bit", 2)):
                (root / machine).mkdir()
                for number in range(1, count + 1):
                    (root / machine / "{:04d}_abc_run.json".format(number)).write_text("{}")
            removed = housekeeping.prune_benchmarks(root, keep=3)
            self.assertEqual(len(removed), 4)
            self.assertEqual(sorted(p.name[:4] for p in (root / "Linux-CPython-3.12-64bit").iterdir()),
                             ["0005", "0006", "0007"])
            self.assertEqual(len(list((root / "Darwin-CPython-3.11-64bit").iterdir())), 2)

    def test_missing_directory_and_command_line(self):
        self.assertEqual(housekeeping.prune_benchmarks(Path("/nonexistent/benchmarks"), keep=5), [])
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(housekeeping.main(["prune-benchmarks", "--keep", "2", "--dir", tmp]), 0)
            with self.assertRaises(SystemExit):
                housekeeping.main(["prune-benchmarks", "--keep", "0", "--dir", tmp])

    def test_empty_machine_directories_are_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Linux").mkdir()
            housekeeping.prune_benchmarks(Path(tmp), keep=1)
            self.assertFalse((Path(tmp) / "Linux").exists())
