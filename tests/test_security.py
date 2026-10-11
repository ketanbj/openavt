"""Check attacks that the unauthenticated link CRC alone cannot prevent."""

import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from openavt import pki
from openavt.demos import loopback
from openavt.tls import Endpoint


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tls-audio-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        pki.issue_certificates(self.directory, rogue=False)
        self.audio = self.directory / "audio"
        self.audio.mkdir()
        self.link = loopback.AudioLink(self.audio, impairments=False)
        self.agent, self.desk = pki.endpoints(self.directory)

    def deliver_wire(self, ciphertext):
        # The attacker can create new frames with valid sequence numbers and
        # valid CRCs. Delivery must still traverse the WAV modem.
        outgoing = ssl.MemoryBIO()
        outgoing.write(ciphertext)
        self.link.transfer(SimpleNamespace(name="agent", outgoing=outgoing), self.desk)

    def test_ciphertext_tampering_survives_crc_but_fails_tls(self):
        loopback.handshake(self.agent, self.desk, self.link)
        self.agent.tls.write(b"authoritative request\n")
        ciphertext = bytearray(self.agent.outgoing.read())
        ciphertext[-1] ^= 1
        self.deliver_wire(bytes(ciphertext))
        with self.assertRaises(ssl.SSLError):
            self.desk.tls.read(16384)

    def test_replayed_application_record_fails_tls(self):
        loopback.handshake(self.agent, self.desk, self.link)
        plaintext = b"authoritative request\n"
        self.agent.tls.write(plaintext)
        ciphertext = self.agent.outgoing.read()
        self.deliver_wire(ciphertext)
        self.assertEqual(self.desk.tls.read(16384), plaintext)
        self.deliver_wire(ciphertext)
        with self.assertRaises(ssl.SSLError):
            self.desk.tls.read(16384)

    def test_client_without_certificate_is_rejected(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(str(self.directory / "root.pem"))
        context.set_ecdh_curve("prime256v1")
        anonymous = Endpoint("agent", context, server_hostname="desk.demo")
        with self.assertRaises(ssl.SSLError):
            loopback.handshake(anonymous, self.desk, self.link)


if __name__ == "__main__":
    unittest.main()
