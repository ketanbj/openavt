"""Exercise installed CLI dispatch and package imports, including a real WAV run."""

import json
import subprocess
import sys

import pytest

from openavt import __version__


@pytest.mark.parametrize(
    "arguments, expected",
    [
        (["--version"], f"openavt {__version__}"),
        (["--help"], "loopback"),
        (["loopback", "--help"], "--scenario"),
        (["live", "--help"], "--env-file"),
        (["ava", "--help"], "enroll"),
        (["delegation-demo", "--help"], "--agents"),
        (["sdk-demo", "--help"], "twilio-live"),
    ],
)
def test_installed_module_cli(arguments, expected):
    result = subprocess.run(
        [sys.executable, "-I", "-m", "openavt", *arguments], capture_output=True, text=True, check=True
    )
    assert expected in result.stdout


def test_loopback_runs_from_another_working_directory(tmp_path):
    subprocess.run(
        [sys.executable, "-I", "-m", "openavt", "loopback", "--scenario", "valid"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    report = json.loads((tmp_path / "output/valid/trace.json").read_text())
    assert report["tls_version"] == "TLSv1.3"
    assert report["result"] == "allowed"
    assert report["response"]["status"] == "shipped"
