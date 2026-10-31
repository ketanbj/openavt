# OpenAVT documentation

OpenAVT protects structured requests carried through audio. Customer permission
is enforced separately; ordinary speech remains outside that inner channel.

| Goal | Read |
|---|---|
| Understand the business case | [README](../README.md), [business guide](business.md) |
| Run local SDK peers without an API key | [Quickstart](quickstart.md) |
| Find the right source/test file | [Code map](code-map.md) |
| Install, contribute or validate a package | [Development](development.md), [contributing](../CONTRIBUTING.md) |
| Understand the audio path | [Architecture](architecture.md) |
| Understand identity versus delegated permission | [Authority](authority.md), [persistent authority CLI](authority-cli.md) |
| Integrate a session/gateway or provider | [SDK integration](integration.md) |
| Use QUIC, PAP or risk monitoring | [QUIC](quic.md), [PAP](pap.md), [risk](risk.md) |
| Inspect measured results | [Verification](verification.md), [performance](performance.md) |
| Reproduce the authority limitation study | [Method](authority-experiment.md), [recorded results](experiments/authority-2026-10-31.md) |
| Read/rebuild the manuscript | [Paper guide](../paper/README.md) |
| Understand release automation | [Release guide](releasing.md) |
| Work as a coding agent | [AGENTS.md](../AGENTS.md) |

## Read results in context

Transport delivery, certificate identity, delegated permission and the eventual
business effect are different boundaries. This gateway checks authorization
before invoking an application handler; a later remote or physical effect needs
its own commit semantics. Local PCMU/WebRTC evidence does not establish public
carrier or microphone compatibility. Historical report counts/timings describe
their named revision and environment.

The sight/tactile projects use an independent shared-core profile. Membership in
OpenModalityTrust does not make OpenAVT consume that profile or draft schemas.
