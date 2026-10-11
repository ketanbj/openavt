# Quickstart

[README](../README.md) · [Performance](performance.md) · [Authority](authority.md)

Requires Python 3.11+, `uv` and the `openssl` executable. The demos are tested on
Linux and macOS. Run these commands from a checkout:

```sh
git clone https://github.com/ketanbj/openavt.git
cd openavt
```

## Start with enrollment and delegation

```sh
uv run --locked --extra webrtc --extra authority openavt delegation-demo
```

This starts a temporary AVA service, enrolls and renews an agent certificate,
issues a customer grant, then verifies one allowed request and seven denials
over live audio TLS. It needs no OpenAI key. See [the authorization cases](authority.md#demo-cases).

## Add two OpenAI voice agents

```sh
cp -n .env.example .env
# Set OPENAI_API_KEY in .env locally.
uv run --locked --extra agents --extra authority openavt delegation-demo --agents
```

Each agent has its own LLM context, transcribes received speech and speaks with
synthesized audio. The allowed request comes from the caller's tool invocation;
the seven denial probes are deterministic. Backend permission checks run outside
the LLM. This mode uses paid OpenAI API calls.

The CLI reads `.env` from the working directory, or a file passed with
`--env-file PATH`. Existing environment variables take precedence. Model settings
are listed in [.env.example](../.env.example). `cp -n` preserves an existing `.env`.

## Other demos

| Goal | Command | Extras |
| --- | --- | --- |
| WAV loopback, core dependencies only | `openavt loopback --scenario valid` | None |
| Fast live audio TLS with a fixture certificate | `openavt live --transport-only --profile pcm` | `webrtc` |
| Voice-band FSK instead of digital PCM | `openavt live --transport-only --profile voiceband` | `webrtc` |
| Two OpenAI agents with a fixture grant | `openavt live --profile pcm` | `agents` |
| Persistent enrollment service | `openavt ava --help` | `authority` |

With `uv`, run a table command as `uv run --locked --extra webrtc openavt ...`,
substituting the listed extras. Omit `--extra` for the core loopback demo.
`live` and `loopback` support `--scenario valid|scope|loss|untrusted`.
[Persistent AVA setup](authority-cli.md) covers enrollment and customer grants.

## Install with pip

In an activated virtual environment, install from the checkout:

```sh
python -m pip install -e '.[webrtc,authority]'
openavt delegation-demo
```

Use `.[agents,authority]` for the OpenAI demo. Other extras are `audio` for the
streaming modem and `authority` for enrollment without audio dependencies.
The core package has no pip dependencies. `python -m openavt` is equivalent to
the installed `openavt` command. PyPI publication is pending.

## Reports and common issues

Demos write `report.json`, WAV recordings and traces to unique directories in
`output/`. Temporary private keys are removed after the call. Tokens are redacted
in delegation traces. A path passed with `--output PATH` must be empty.

| Symptom | Check |
| --- | --- |
| Missing optional dependency | Include the extras required by the selected demo |
| Missing OpenAI key | Configure `.env`, or use the demo without `--agents` |
| Handshake takes about 30 seconds | Select `--profile pcm` for `live`; its default is 1 kbps FSK |
| PCM fails after audio processing | Preserve the 8 kHz PCMU samples; avoid transcoding, mixing and gain changes |

The PCM profile rejects Opus. All reported fast results use an unchanged digital
PCMU path. [Timing and transport limits](performance.md#timing-and-scope).
