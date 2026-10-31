"""Smoke tests for runnable example scripts."""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = [
    "full_agent_flow.py",
]


def test_examples_run_successfully(tmp_path):
    env = os.environ.copy()
    # Exercise the installed wheel/editable package. Prepending the source directory
    # hides the compiled extension and does not represent an installed product.
    env["PYTHONIOENCODING"] = "utf-8"

    for example in EXAMPLES:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "examples" / example)],
            cwd=tmp_path,
            env=env,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, (
            f"{example} failed with exit code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
