"""Install the core wheel in a clean environment and run outside the checkout."""

import json
import subprocess
import tempfile
import venv
from pathlib import Path

from openavt import __version__


def main() -> None:
    wheels = list(Path("dist").glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in dist/")
    wheel = wheels[0].resolve()
    with tempfile.TemporaryDirectory(prefix="openavt-wheel-") as temporary:
        work = Path(temporary)
        environment = work / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / "bin/python"
        cli = environment / "bin/openavt"
        subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], check=True)
        version = subprocess.run(
            [str(cli), "--version"], cwd=work, check=True, capture_output=True, text=True
        )
        assert version.stdout.strip() == f"openavt {__version__}"
        print(version.stdout.strip())
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.util; import importlib.metadata; import openavt; "
                "assert importlib.metadata.version('openavt') == openavt.__version__; "
                "assert importlib.util.find_spec('numpy') is None; "
                "assert importlib.util.find_spec('openai') is None",
            ],
            cwd=work,
            check=True,
        )
        missing = subprocess.run(
            [str(cli), "live", "--transport-only"], cwd=work, capture_output=True, text=True
        )
        assert missing.returncode == 2
        assert "pip install 'openavt[webrtc]'" in missing.stderr
        missing_authority = subprocess.run(
            [str(cli), "ava", "--help"], cwd=work, capture_output=True, text=True
        )
        assert missing_authority.returncode == 2
        assert "pip install 'openavt[authority]'" in missing_authority.stderr
        subprocess.run([str(cli), "loopback", "--scenario", "valid"], cwd=work, check=True)
        report = json.loads((work / "output/valid/trace.json").read_text())
        assert report["tls_version"] == "TLSv1.3"
        assert report["result"] == "allowed"
        assert report["response"]["status"] == "shipped"
    print("Core wheel installed cleanly and completed mutual TLS outside the checkout.")


if __name__ == "__main__":
    main()
