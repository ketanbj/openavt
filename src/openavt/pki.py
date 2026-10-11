"""Ephemeral demonstration certificates; not a production certificate authority."""

import shutil
import ssl
import subprocess
from pathlib import Path

from openavt.tls import Endpoint


def openssl(*args: str) -> None:
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("The demo requires the openssl executable on PATH.")
    result = subprocess.run([executable, *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())


def issue_certificates(directory: Path, rogue: bool) -> None:
    def key(name: str) -> None:
        openssl(
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(directory / f"{name}.key"),
        )
        (directory / f"{name}.key").chmod(0o600)

    key("root")
    openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        str(directory / "root.key"),
        "-out",
        str(directory / "root.pem"),
        "-days",
        "1",
        "-sha256",
        "-subj",
        "/CN=OpenAVT demo root",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    for name, subject, san, purpose in (
        ("desk", "desk.demo", "DNS:desk.demo", "serverAuth"),
        ("agent", "demo-agent", "URI:urn:demo:agent:assistant", "clientAuth"),
    ):
        key(name)
        openssl(
            "req",
            "-new",
            "-key",
            str(directory / f"{name}.key"),
            "-out",
            str(directory / f"{name}.csr"),
            "-subj",
            f"/CN={subject}",
        )
        extensions = directory / f"{name}.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
        )
        if name == "agent" and rogue:
            # A validly formed but untrusted client certificate.
            openssl(
                "x509",
                "-req",
                "-in",
                str(directory / "agent.csr"),
                "-signkey",
                str(directory / "agent.key"),
                "-out",
                str(directory / "agent.pem"),
                "-days",
                "1",
                "-sha256",
                "-extfile",
                str(extensions),
            )
        else:
            openssl(
                "x509",
                "-req",
                "-in",
                str(directory / f"{name}.csr"),
                "-CA",
                str(directory / "root.pem"),
                "-CAkey",
                str(directory / "root.key"),
                "-set_serial",
                "2" if name == "desk" else "3",
                "-out",
                str(directory / f"{name}.pem"),
                "-days",
                "1",
                "-sha256",
                "-extfile",
                str(extensions),
            )


def endpoints(directory: Path) -> tuple[Endpoint, Endpoint]:
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    for context, name in ((client_context, "agent"), (server_context, "desk")):
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(str(directory / "root.pem"))
        context.load_cert_chain(str(directory / f"{name}.pem"), str(directory / f"{name}.key"))
        context.verify_mode = ssl.CERT_REQUIRED
        # Keep this bandwidth experiment small and reproducible. P-256 is a
        # standard TLS group; this does not measure hybrid/PQ handshakes.
        context.set_ecdh_curve("prime256v1")
    server_context.num_tickets = 0
    return Endpoint("agent", client_context, server_hostname="desk.demo"), Endpoint(
        "desk", server_context, server=True
    )
