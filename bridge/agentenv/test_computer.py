"""Source-owned tests for the agentenv computer launcher's protocol."""

import json
import os
import subprocess
import sys
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "computer.py")


class UsageTests(unittest.TestCase):
    def test_missing_bundle_writes_one_json_error_line_and_exits_2(self):
        done = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(done.returncode, 2)
        lines = done.stdout.splitlines()
        self.assertEqual(len(lines), 1, done.stdout)
        self.assertEqual(json.loads(lines[0]), {"error": "usage: computer.py <bundle folder> [task]"})
        self.assertNotIn("Traceback", done.stderr)


if __name__ == "__main__":
    unittest.main()
