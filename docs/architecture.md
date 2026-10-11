# OpenAVT architecture and library usage

```text
Structured authoritative request / response
OpenSSL mutual TLS 1.3 through MemoryBIO
Reliable ordered byte stream: framing, sequence, CRC, audio ACK, retry
Binary FSK: 1,000 / 2,000 Hz, 1,000 gross bits/s, 8 kHz PCM
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
through tone generation, audio RTP, audio decoding, frame validation, and
MemoryBIO. Recordings are evidence/listening artifacts, not the delivery path.

The receiver assumes stable sample timing within a frame. It does not recover
clock drift. Gross bitrate excludes headers, ACKs, retries, and turnaround gaps.
