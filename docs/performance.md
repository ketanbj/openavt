# Sub-second TLS over audio

[README](../README.md) · [Quickstart](quickstart.md) · [Verification](verification.md)

**Five fresh calls on `main`: 0.561 s median, 0.581 s maximum.**
Every call authenticated both peers and delivered a protected request/response.

## Measured results

| Experiment | Full mTLS handshake | Evidence |
| --- | ---: | --- |
| `main` Linux CI, 5 fresh PCM calls, October 11, 2026 | **0.561 s median · 0.581 s max** | [JSON](performance/pcm-ci-main.json) · [CI run](https://github.com/ketanbj/openavt/actions/runs/38150046644) |
| Two OpenAI agents, AVA enrollment and customer delegation | **0.623 s** | [JSON](authority-verification.json) |
| Installed wheel, AVA demo without OpenAI | **0.582 s** | [JSON](authority-verification.json) |
| Earlier macOS PCM benchmark, 20 fresh calls | 0.621 s median · 0.624 s max | [JSON](performance/pcm-20-calls.json) |

The CI run used Linux x86_64, Python 3.13.16, OpenSSL 3.0.13, aiortc 1.15.0 and
PyAV 17.1.0. All five calls had fresh P-256 certificates and TLS contexts,
no session reuse, no retries and no bad modem frames. Environment details and
per-call timings are in the JSON. The older 20-call run is a separate macOS sample.

## Reproduce

From the checkout, run one live transport-only call:

```sh
uv run --locked --extra webrtc openavt live --transport-only --profile pcm
```

Or measure five fresh calls and fail if any handshake reaches one second:

```sh
uv run --locked --extra webrtc python scripts/benchmark_handshake.py \
  --runs 5 --profile pcm --output output/new-pcm-benchmark \
  --require-under-one-second
```

Use a new output path each time. The benchmark saves reports, recordings and
`summary.json`. Linux CI runs the same threshold check and uploads its summary.
The [complete enrollment demo](quickstart.md#start-with-two-independent-sdk-peers)
also runs the fast PCM profile.

## Timing and scope

The timer starts when the client initiates inner TLS and ends after **both peers
authenticate and the final flight is acknowledged over audio**. It excludes
certificate creation, ICE/DTLS/SRTP call setup, stream warmup and LLM/speech time.
It measures TLS on an established call, rather than total dialing time.

Both peers run on one machine using real UDP/SRTP and native G.711 PCMU audio.
Every TLS record passes through the modem and receiver; there is no data channel.
No TLS tickets, PSK resumption or 0-RTT are used.

The fast profile needs unchanged 8 kHz PCMU samples. Transcoding, gain control,
noise suppression, mixing, resampling and analog playback can break it. Opus is
rejected. Network RTT, jitter, loss and larger certificate chains increase time;
these figures do not establish Internet, carrier/PSTN or microphone performance.
Speech alternates with modem bursts; overlapping speech is unsupported.

## Why it is faster

The original 1 kbps FSK handshake took **31.824 s** while TLS computation used
about **5.4 ms**: transmission was the bottleneck. [Baseline profile](performance/baseline.json).

| Change | Effect |
| --- | --- |
| Seven modem bits per 8 kHz sample | 56 kbps raw data inside 64 kbps PCMU audio payload |
| 4,096-byte frames | Each current TLS flight fits in one frame |
| Remove the 80 ms modem turnaround pause | Shorter flight delivery |
| Reduce jitter prefetch from 80 ms to 20 ms | Lower local latency, less jitter tolerance |

The jitter adapter is guarded and limited to aiortc 1.15. Certificate validation,
encryption and mutual authentication remain enabled. Headers, ACKs and retries
reduce application throughput below the raw modem rate.

Public summaries omit credentials and transcripts. Capture hashes identify local
reports and WAVs, which are not public independent verification artifacts.
Earlier [agent](performance/pcm-agents.json) and [wheel](performance/pcm-wheel.json)
measurements remain available as historical evidence.

[Architecture](architecture.md) · [G.711 RTP](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.14)
