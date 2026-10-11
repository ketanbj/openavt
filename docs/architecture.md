# OpenAVT architecture and library usage

```text
Structured authoritative request / response
OpenSSL mutual TLS 1.3 through MemoryBIO
Reliable ordered byte stream: framing, sequence, CRC, audio ACK, retry
Audio modem: 1 kbps FSK, or 56 kbps digital G.711 PCM
WAV loopback or live G.711/PCMU WebRTC audio
```

`openavt.protocol` contains the standard-library waveform and frame format.
`openavt.modem.StreamDecoder` acquires preambles in arbitrary incoming sample chunks
and validates the reconstructed frames. `openavt.channel.AudioTLS` handles
stop-and-wait delivery and supplies decoded bytes to a MemoryBIO TLS endpoint.
The library modules have no dependency on the demo application.

## Core helpers

```python
from openavt.protocol import DATA, frame, modulate, demodulate, unframe

wire = frame(0, DATA, b"example TLS bytes")
assert unframe(demodulate(modulate(wire))) == (0, DATA, b"example TLS bytes")
```

This example only demonstrates framing; it does not perform a TLS handshake.
TLS endpoints wrap your own configured `ssl.SSLContext`:

```python
import ssl
from openavt.tls import Endpoint

context = ssl.create_default_context(cafile="your-trust-root.pem")
context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain("client.pem", "client.key")
endpoint = Endpoint("client", context, server_hostname="service.example")
# endpoint.incoming / outgoing are MemoryBIOs; endpoint.tls is the SSLObject.
```

For a live audio integration, `AudioTLS(endpoint, send_audio, log)` accepts an
async `send_audio(samples, kind)` callback. Run `session.run(initiate=True)` for
the client and `session.run()` for the server. Feed verified decoded modem frames
to `session.receive_frame(sequence, kind, payload)`. Await `wait_ready()` before
`send_json()` / `receive_json()`. Cancel the run tasks and await `close()` when the
transport closes. `transports/webrtc.py` and `demos/live.py` show the complete
wiring, timing, speech separation, and task cleanup.

`pki.issue_certificates()` and `pki.endpoints()` are demo-only utilities. They
create ephemeral P-256 certificates and contexts for `desk.demo` and the fixed
URI agent identity, require mutual authentication, disable session tickets, and
use P-256 key exchange to keep the audio experiment small. The generic Endpoint
uses the context supplied by the caller and does not override its trust policy.

## Trust boundary

TLS authenticates certificate/key possession and protects structured messages.
The backend fixture policy independently checks the certificate URI, action, and
resource. LLM speech cannot change that grant. Speech remains outside the inner
TLS channel. The outer WebRTC transport independently uses SRTP.

WebRTC SDP establishes the peers out of band but carries no inner TLS records or
application messages. There is no data channel. Every inner TLS record passes
through waveform generation, audio RTP, audio decoding, frame validation, and
MemoryBIO. Recordings are evidence/listening artifacts, not the delivery path.

The receiver assumes stable sample timing within a frame. It does not recover
clock drift. Gross bitrate excludes headers, ACKs, retries, and turnaround gaps.

## Fast digital PCM profile

Use `AudioTLS(endpoint, send_audio, log, profile="pcm")` with
`openavt.pcm.StreamDecoder` and an unchanged 8 kHz mono PCMU path.
`AudioCall(..., profile="pcm")` wires this configuration for the demo.
The PCM modem selects one of 128 exact mu-law reconstruction levels for each
7-bit symbol. The native G.711 encoder and decoder preserve those sample values.
A fixed 32-sample prefix acquires sample alignment, and the existing sequence,
kind, bounded length and CRC frame format validates delivery. TLS still verifies
certificates and authenticates the application records.

The fast profile allows 4,096-byte frames, so each current TLS flight fits in one
audio frame, and omits the 80 ms modem turnaround gap. Speech keeps its pause.
The demo reduces aiortc's audio jitter prefetch from four 20 ms packets to one;
this trades network jitter tolerance for latency on the measured local path.
There is no public aiortc setting for this, so a guarded adapter accesses the
1.15 jitter buffer and the dependency is constrained to `>=1.15,<1.16`.
Incompatible layouts raise an error. Codec payloads and decoding remain native.

This profile needs a digital path that preserves samples. It does not claim
56 kbps through analog telephone audio, arbitrary VoIP processing, or Opus.
The default FSK profile retains its previous framing and buffering settings.
See [measured performance](performance.md) for the timing boundary and evidence.


## Authority and delegation

`authority/ca.py` implements local pseudonymous client-certificate enrollment.
`authority/service.py` and `client.py` expose bounded JSON account/order/key-proof
and consent APIs. These APIs operate outside the call, using HTTP on loopback or
HTTPS with normal server verification. They are not ACME-compatible. Agent
private keys never appear in API requests, and client roots are supplied out of band.

`authority/delegation.py` holds a separate business Ed25519 signing key and pinned
verification key. Operator-provisioned customer credentials and account-resource
policy authorize five-minute maximum, single-use certificate-bound grants. The
backend verifies issuer, audience, certificate, customer, scope, expiry and current
revocation status, then atomically consumes a protected business challenge and
grant in SQLite. Checks precede the fixed read-only response and run outside the LLM.

The enrollment credential cannot authorize customer account access. The AVA root
key is never a business consent signer. `demos/delegation.py` shows the full flow,
including an established TLS session whose certificate is subsequently revoked:
its next business request is denied by the application status check. Ordinary
OpenSSL certificate validation alone does not consult this prototype's registry.
See [authority operation and limits](authority.md).
