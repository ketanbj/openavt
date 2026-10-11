# Sub-second full mutual TLS over a 64 kbps audio channel

The opt-in `pcm` profile reached the target on live local WebRTC audio:

| Measurement | Handshake | Protected request/response |
| --- | ---: | ---: |
| Original 1 kbps FSK, profiled transport call | 31.824 s | 3.214 s |
| PCM, 20 fresh calls, median | 0.621 s | 0.199 s |
| PCM, 20 fresh calls, p95 / maximum handshake | 0.623 / 0.624 s | — |
| PCM, two real GPT-6.1 Sol agents | 0.585 s | 2.937 s |

All 20 benchmark calls authenticated both peers, used no resumed TLS session,
and delivered a verified protected request and response. They had zero link
retries and zero bad modem frames. The agent run made five LLM requests, four
TTS requests and three transcriptions across two independent agent contexts;
its request/response includes desk transcription and LLM processing. Total
agent-call time was 48.725 s, including ordinary speech and API calls.

## Profile first

The original implementation was measured with `cProfile` before changes.
The stdlib TLS handshake calls consumed approximately **5.4 ms**, while the
full handshake took **31.824 s**. The baseline generated fourteen DATA frames
and fourteen audio ACKs. Approximately 2.94 KB of TLS handshake records plus
frame overhead occupied **29.6 s** of 1 kbps modem audio. Crypto optimization
could not remove that transmission time.

The changes address that bottleneck:

- A digital PCM modem sends seven bits per 8 kHz sample, selecting one of 128
  exact G.711 mu-law reconstruction levels: **56,000 raw modem bits/s**.
- G.711 PCMU still sends eight bits per sample: **64,000 audio payload bits/s**,
  excluding RTP/SRTP/UDP/IP headers. This is not a claim of 64 kbps application
  throughput. The native codec remains in the delivery path.
- A 4,096-byte frame limit lets each current TLS flight fit into one DATA frame.
  The current full handshake needs three flights, roughly 517, 1,335, and 1,090
  bytes; ECDSA signatures cause small size variations.
- Modem transmission omits the previous 80 ms turnaround pause. Speech retains
  its pause. Local audio jitter prefetch drops from 80 ms to 20 ms through a
  guarded aiortc 1.15 adapter; the dependency is constrained to that minor release.

Three flights and three ACKs take approximately **0.49 s of audio** at this
modem rate, including prefixes, frame headers, CRCs and trailing samples. The
measured median of 0.621 s includes packet alignment, buffering, ACK delivery,
and TLS computation. No certificate checks, encryption or mutual authentication
were removed. Session tickets remain disabled in the demo, P-256 key exchange
remains unchanged, and every measurement uses fresh TLS contexts and demo keys.

## Timing and scope

The timer starts immediately before the client initiates inner TLS and ends
when both endpoints have authenticated and the client's final flight has been
acknowledged **over audio**. It excludes certificate generation, ICE/DTLS/SRTP
call establishment, a 300 ms stream warmup, and preceding speech. This measures
a cold inner TLS handshake on an established voice call, not total dialing time.
TLS tickets, PSK resumption and 0-RTT are not used.

Both peers run in one process on the same machine, using real UDP/SRTP audio,
native PCMU encoding/decoding, and receiver-side waveform reconstruction. SDP
is the only out-of-band peer exchange. There is no data channel and no TLS byte
delivery through recordings. The machine was macOS arm64, Python 3.13.10,
OpenSSL 3.6.3, aiortc 1.15.0 and PyAV 17.1.0; the evidence records the environment.

This is a **digital G.711 path** result. The modem requires exact reconstruction
levels and stable sample timing; AGC, noise suppression, mixing, resampling,
lossy transcoding, or microphone/speaker playback can destroy them. `--codec
opus --profile pcm` is rejected. The lower prefetch also reduces tolerance for
network jitter. Arbitrary Internet/PSTN calls, packet-loss concealment, larger
certificate chains, and hybrid/post-quantum key exchanges have not met this
target. Longer network RTTs or ARQ retries increase the measured handshake.
Speech alternates with audible noise-like modem bursts; simultaneous speech
is not supported. The default voice-band FSK profile remains available.

## Evidence and reproduction

Public evidence omits call transcripts, application identifiers, certificate
files and credentials. SHA-256 hashes connect the summaries to the original
local reports and recordings, which remain in ignored `output/` directories.
They identify those artifacts; they are not independently verifiable call captures.

- [Baseline profile](performance/baseline.json): original revision, frame sizes,
  profiler CPU measurements, handshake and transport results.
- [20-call PCM benchmark](performance/pcm-20-calls.json): individual fresh-call
  timings, per-flight deliveries, session reuse flags, modem counters, RTP stats
  and aggregate median/p95/maximum.
- [Two-agent result](performance/pcm-agents.json): model/API counters, timings,
  protected workflow verification, TLS, modem and RTP statistics.
- [Installed-wheel call](performance/pcm-wheel.json): a fresh environment with
  the non-editable wheel completed mTLS in **0.621 s**, then the protected
  request/response in **0.198 s**. Core wheel loopback, build metadata and archive
  checks also passed. All **29 automated tests** passed locally.

From a checkout with the `webrtc` extra:

```sh
uv sync --locked --extra webrtc
uv run --locked --extra webrtc openavt live --transport-only --profile pcm
uv run --locked --extra webrtc python scripts/benchmark_handshake.py \
  --runs 20 --profile pcm --output output/new-pcm-benchmark \
  --require-under-one-second
uv run --locked --extra webrtc pytest -q
```

The benchmark makes sequential calls with fresh CA keys, certificates, TLS
contexts and WebRTC peers. It saves full local reports/audio plus a public
summary, and the optional threshold fails if **any** measured handshake takes
one second or more. Use a new output path for each invocation. Linux CI runs
five calls with that threshold and uploads the summary alongside distributions.
Functional tests cover real live success, denied scope, one damaged waveform
plus one dropped audio ACK, untrusted client rejection, native codec preservation
of all 128 levels, arbitrary sample boundaries, bounded frame sizes, corruption
recovery, and TLS ciphertext tampering/replay despite valid frame CRCs.

To run the real agents with a locally configured key:

```sh
uv sync --locked --extra agents
uv run --locked --extra agents openavt live --profile pcm
```

References: [G.711 RTP encoding, RFC 3551 §4.5.14](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.14),
[TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html),
and [architecture and trust boundary](architecture.md).
