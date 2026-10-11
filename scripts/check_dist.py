"""Check release names, metadata, entry points, and absence of private artifacts."""

import configparser
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path

from openavt import __version__

PROJECT = "openavt"


def check_contents(names: list[str]) -> None:
    forbidden = {".env", "output", ".git", "__pycache__"}
    for name in names:
        path = Path(name)
        if (
            forbidden.intersection(path.parts)
            or any(part.startswith(".venv") for part in path.parts)
            or (path.name.startswith(".env.") and path.name != ".env.example")
            or path.suffix in {".key", ".wav", ".pyc"}
        ):
            raise SystemExit(f"Unexpected local/private artifact in distribution: {name}")
    if not any(Path(name).name == "LICENSE" for name in names):
        raise SystemExit("Distribution is missing LICENSE")
    if not any(name.endswith(f"{PROJECT}/protocol.py") for name in names):
        raise SystemExit("Distribution is missing core package code")


def check_metadata(raw: bytes) -> None:
    metadata = BytesParser().parsebytes(raw)
    if metadata["Name"] != PROJECT or metadata["Version"] != __version__:
        raise SystemExit("Distribution name/version does not match OpenAVT")
    if metadata["License-Expression"] != "Apache-2.0":
        raise SystemExit("Distribution license does not match Apache-2.0")
    if set(metadata.get_all("Provides-Extra", [])) != {"audio", "webrtc", "agents"}:
        raise SystemExit("Distribution is missing an optional integration extra")
    if "# OpenAVT" not in metadata.get_payload():
        raise SystemExit("Distribution README is missing the OpenAVT title")


def main() -> None:
    directory = Path("dist")
    wheels = list(directory.glob("*.whl"))
    sources = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise SystemExit("Expected exactly one wheel and one source distribution in dist/")
    if wheels[0].name != f"{PROJECT}-{__version__}-py3-none-any.whl":
        raise SystemExit("Unexpected wheel name/version")
    if sources[0].name != f"{PROJECT}-{__version__}.tar.gz":
        raise SystemExit("Unexpected source distribution name/version")
    with zipfile.ZipFile(wheels[0]) as wheel:
        check_contents(wheel.namelist())
        info = f"{PROJECT}-{__version__}.dist-info"
        check_metadata(wheel.read(f"{info}/METADATA"))
        if wheel.read(f"{info}/top_level.txt").decode().split() != [PROJECT]:
            raise SystemExit("Wheel contains an unexpected import namespace")
        entries = configparser.ConfigParser()
        entries.read_string(wheel.read(f"{info}/entry_points.txt").decode())
        if dict(entries["console_scripts"]) != {PROJECT: f"{PROJECT}.cli:main"}:
            raise SystemExit("Wheel command-line entry point does not match OpenAVT")
    with tarfile.open(sources[0]) as source:
        check_contents(source.getnames())
        metadata_file = source.extractfile(f"{PROJECT}-{__version__}/PKG-INFO")
        if metadata_file is None:
            raise SystemExit("Source distribution is missing metadata")
        check_metadata(metadata_file.read())
    print("OpenAVT names, metadata, extras, CLI, license, and archive contents verified.")


if __name__ == "__main__":
    main()
