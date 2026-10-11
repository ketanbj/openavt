# OpenAVT

**TLS over voice. Built for agents.**

OpenAVT (**Open Agent Voice TLS**) is an experimental Python package that carries
**real mutual TLS 1.3 records as voice-band FSK tones**. It includes a WAV loopback proof and a live local WebRTC
call between two OpenAI voice agents.

The TLS implementation is Python's OpenSSL-backed `ssl.MemoryBIO`. The audio link
provides framing, CRC, audio acknowledgements, retransmission, and duplicate
suppression. TLS supplies authentication and cryptographic integrity. The live
demo uses G.711/PCMU over UDP/SRTP, with no WebRTC data channel carrying inner TLS
bytes or application requests.

**Status:** v0.1.0, alpha. Source is available on
[GitHub](https://github.com/ketanbj/openavt); not yet published to PyPI. Requires Python 3.11+ with TLS 1.3 support. The certificate demos also
require the `openssl` executable on PATH. Apache-2.0 licensed.

## Install from this checkout

```sh
git clone https://github.com/ketanbj/openavt.git
cd openavt
uv sync --locked --extra agents
```

Or use pip in a virtual environment:

```sh
python -m pip install -e '.[agents]'
```

Choose dependencies by use case:

| Extra | Provides |
| --- | --- |
| None | Standard-library framing, FSK/WAV helpers, TLS endpoint, loopback demo |
| `audio` | Streaming modem with NumPy and SciPy |
| `webrtc` | Streaming modem and live WebRTC audio transport |
| `agents` | WebRTC plus OpenAI LLM, transcription, and speech integration |

After publication, installation will use `pip install 'openavt[agents]'`.

## Run

With `uv sync`, prefix commands with `.venv/bin/`; a pip-installed virtual
environment provides `openavt` when activated. `python -m openavt` is equivalent.

```sh
# No external APIs or pip dependencies required for this demo.
openavt loopback --scenario valid

# Live WebRTC audio without OpenAI calls.
openavt live --transport-only

# Two real OpenAI agents, using your configured key.
openavt live

# A certified caller requests a mutation outside its read-only grant.
openavt live --scenario scope
```

For the agent call, copy `.env.example` to `.env` and set `OPENAI_API_KEY` locally.
The CLI loads `.env` from the **working directory**, or from `--env-file PATH`;
existing environment variables take precedence. Models are configurable there.
Defaults are `gpt-6.1-sol` for both independent agent contexts, `gpt-transcribe`
for speech recognition, and `gpt-4o-mini-tts` for distinct synthesized voices.

Agents transcribe speech actually received through WebRTC. A fixed backend grant
allows `order.read` for the demo order and rejects `address.change`. The backend
enforces this policy outside the LLM. Structured decisions cross audio TLS;
ordinary speech alternates with tone bursts and is outside that inner TLS session.

Both demos accept `--scenario valid|scope|loss|untrusted` and `--output PATH`.
An explicitly selected output directory must be empty. Default output directories
are unique, so existing captures are preserved.

Live evidence includes `report.json`, incoming endpoint WAVs, a stereo call
recording, and the public demo root certificate. Private keys are temporary and
are never installed in system trust. Local credentials and output are excluded
from source control and distribution archives.

## Layout

```text
src/openavt/
  protocol.py         FSK waveform, frame encoding, CRC, WAV helpers
  tls.py              Transport-independent MemoryBIO TLS endpoint
  pki.py              Ephemeral demo certificates and endpoint factory
  modem.py            Streaming preamble acquisition and frame decoding
  channel.py          Reliable audio framing around the TLS byte stream
  transports/webrtc.py  Live audio-only WebRTC transport
  agents/openai.py    Independent OpenAI agent contexts, ASR and TTS
  demos/              Loopback, live call, fixed fixture policy
  cli.py              Installed command-line entry point
tests/                Streaming, policy, cryptographic and CLI checks
docs/                 Architecture, measurements, release instructions
```

The core modules never import demos or OpenAI. Optional integrations are loaded
only when requested. The 0.x library API is experimental; see
[architecture and library usage](docs/architecture.md).

## Verification

The OpenAVT v0.1.0 wheel completed a live call with two GPT-6.1 Sol agents,
measuring a **32.003 s** mutual TLS handshake and a **5.957 s** protected
request/response. Earlier agent calls also verified denial of an address change. These are local-machine
measurements, not throughput or Internet guarantees; detailed conditions are in
[verified results](docs/verification.md).

```sh
uv run --locked --extra agents pytest -q
uv run --locked --extra agents ruff check src tests scripts
uv run --locked --extra agents ruff format --check src tests scripts
uv run --locked --extra agents python -m build
uv run --locked --extra agents twine check --strict dist/*
```

[Release instructions](docs/releasing.md) describe wheel validation, GitHub
releases, and PyPI Trusted Publishing. CI exercises the installed wheel and live
WebRTC transport without spending OpenAI API credits.

## Current limits

The live demo connects two peers in one process on the same machine. Public
Internet, microphone, telephone carrier, clock drift, FEC, overlapping speech and
tones, and production CA issuance/revocation are not implemented. Only PCMU has
been verified; Opus remains experimental. Certificates and grants are fixtures,
not a customer consent or delegation system. CRC detects link errors; it does
not authenticate them. The tests do not constitute a production security audit.

## References

- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [Python SSL MemoryBIO](https://docs.python.org/3/library/ssl.html#memory-bio-support)
- [ACME, RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html)
- [aiortc](https://aiortc.readthedocs.io/)
