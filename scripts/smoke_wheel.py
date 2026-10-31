"""Install the core wheel in a clean environment and run outside the checkout."""

import argparse
import json
import subprocess
import tempfile
import venv
import zipfile
from email.parser import BytesParser
from pathlib import Path

from openavt import __version__


def main(directory: Path = Path("dist")) -> None:
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in dist/")
    wheel = wheels[0].resolve()
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        extras = BytesParser().parsebytes(archive.read(metadata_name)).get_all("Provides-Extra", [])
    with tempfile.TemporaryDirectory(prefix="openavt-wheel-") as temporary:
        work = Path(temporary)
        environment = work / "venv"
        # Match the POSIX venv CLI: copying managed Python can lose its dylib path.
        venv.EnvBuilder(with_pip=True, symlinks=True).create(environment)
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
        if "quic" in extras:
            missing_quic = subprocess.run(
                [str(cli), "sdk-demo", "--protocol=quic"], cwd=work, capture_output=True, text=True
            )
            assert missing_quic.returncode == 2
            assert "pip install 'openavt[webrtc,authority,quic]'" in missing_quic.stderr
        subprocess.run([str(cli), "loopback", "--scenario", "valid"], cwd=work, check=True)
        report = json.loads((work / "output/valid/trace.json").read_text())
        assert report["tls_version"] == "TLSv1.3"
        assert report["result"] == "allowed"
        assert report["response"]["status"] == "shipped"
        subprocess.run([str(python), "-m", "pip", "install", f"{wheel}[pap]"], check=True)
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.util; from openavt.pap import PAPClient, VoiceBridge; from openavt.risk import RiskMonitor; assert importlib.util.find_spec('numpy') is None; assert importlib.util.find_spec('openai') is None",
            ],
            cwd=work,
            check=True,
        )
        # Only sources declaring QUIC should install it: release retries may be
        # validating immutable wheels built before this optional integration.
        if "quic" in extras:
            subprocess.run([str(python), "-m", "pip", "install", f"{wheel}[quic]"], check=True)
            subprocess.run(
                [
                    str(python),
                    "-I",
                    "-c",
                    "import importlib.util; from openavt.quic import AudioQUIC; "
                    "assert importlib.util.find_spec('aiortc') is None; "
                    "assert importlib.util.find_spec('openai') is None",
                ],
                cwd=work,
                check=True,
            )
    print(
        "Optional wheel imports verified. Core wheel installed cleanly and completed mutual TLS outside the checkout."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist", type=Path, default=Path("dist"), help="directory containing the archive pair"
    )
    main(parser.parse_args().dist)
