"""A newer publishing helper must validate immutable artifacts from older sources."""

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "check_dist", Path(__file__).parents[1] / "scripts/check_dist.py"
)
check_dist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_dist)


def archives(directory, declared, wheel_extras=None, source_extras=None):
    directory.mkdir()
    version = check_dist.__version__
    prefix = f"openavt-{version}"

    def metadata(extras):
        return (
            f"Metadata-Version: 2.4\nName: openavt\nVersion: {version}\nLicense-Expression: Apache-2.0\n"
            + "".join(f"Provides-Extra: {extra}\n" for extra in sorted(extras))
            + "\n# OpenAVT\n"
        ).encode()

    project = '[project]\nname = "openavt"\n[project.optional-dependencies]\n' + "".join(
        f"{extra} = []\n" for extra in sorted(declared)
    )
    with tarfile.open(directory / f"{prefix}.tar.gz", "w:gz") as source:
        for name, content in {
            "pyproject.toml": project.encode(),
            "PKG-INFO": metadata(declared if source_extras is None else source_extras),
            "LICENSE": b"Apache-2.0",
            "src/openavt/protocol.py": b"",
        }.items():
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(content)
            source.addfile(info, io.BytesIO(content))
    with zipfile.ZipFile(directory / f"{prefix}-py3-none-any.whl", "w") as wheel:
        for name, content in {
            "openavt/protocol.py": b"",
            f"{prefix}.dist-info/METADATA": metadata(declared if wheel_extras is None else wheel_extras),
            f"{prefix}.dist-info/top_level.txt": b"openavt\n",
            f"{prefix}.dist-info/entry_points.txt": b"[console_scripts]\nopenavt = openavt.cli:main\n",
            f"{prefix}.dist-info/licenses/LICENSE": b"Apache-2.0",
        }.items():
            wheel.writestr(name, content)


@pytest.mark.parametrize(
    "extras",
    [
        {"audio", "webrtc", "agents", "authority", "twilio"},
        {"audio", "webrtc", "agents", "authority", "twilio", "pap"},
    ],
)
def test_older_and_current_release_contracts_are_both_valid(tmp_path, monkeypatch, extras):
    archives(tmp_path / "dist", extras)
    monkeypatch.chdir(tmp_path)
    check_dist.main()


@pytest.mark.parametrize("changed", ["wheel", "source"])
@pytest.mark.parametrize("invalid", [{"webrtc"}, {"webrtc", "pap", "unexpected"}])
def test_missing_or_added_extras_fail_against_declared_source(tmp_path, monkeypatch, changed, invalid):
    archives(tmp_path / "dist", {"webrtc", "pap"}, **{f"{changed}_extras": invalid})
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit, match="optional integration extra"):
        check_dist.main()
