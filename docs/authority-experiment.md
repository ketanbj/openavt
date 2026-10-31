# Authority continuity experiment

The completed [October 31 measurements](experiments/authority-2026-10-31.md)
and compressed raw report accompany this method.

This experiment tests whether changing OpenAVT's protected audio transport adds an
authorization property. The control is TLS 1.3 with the existing audio ARQ; the
candidate is QUIC v1. Both use exactly the same certificate authority, PAP/DPoP
HTTPS grant issuance, business permission checks, signed certificate-bound grants,
single-use challenges, and receiving Gateway. This isolates the transport change.
It is not an independent implementation of OAuth, AuthLoop, ACME, or SPIFFE.

The executable is [experiment_authority.py](../scripts/experiment_authority.py).
It creates real local PCMU WebRTC peers, transports protected messages only as
audio, and verifies mutual authentication. There is no WebRTC data channel.
PAP authentication, simulated user consent, grant issuance and sign-out use the
existing certificate-verified local HTTPS service. All credentials are ephemeral
and deleted after each trial. The CA account/order/proof/finalize/revoke APIs run
locally; this does not measure Internet enrollment or an independently operated CA.

Each trial opens five fresh audio calls, including simultaneously open calls with
the same certificate, a reconnect, and a call with a newly enrolled key. Two
legitimate requests also execute concurrently. Key re-enrollment is explicit;
neither transport implements automatic cross-gateway handoff or transfer epochs.
Protocol-rejected calls close before a fresh call is used for recovery.

The attacker can construct protected application requests from a mutually
authenticated endpoint and reuse previously obtained grants. It cannot forge the
authority's signatures. Trials substitute arguments, actions, resources,
customers, request IDs, grants and complete transactions. Fresh per-call
challenges remain part of the control; removing them would weaken the baseline.

The handler appends to an in-memory synthetic effect ledger, recording whether the
business session and requested permission are still active at that point. No real
customer data, account or business action is involved. A schema accepts both blue
and green replacements, while business permission permits blue; argument
substitution must therefore reach authorization rather than be stopped by an
overly restrictive schema. Each trial asserts actual effect counts as well as
response results. Timeouts or transport errors abort the experiment; they are not
counted as authorization denials.

Three repetitions cover both transports with clean audio and with the existing
deterministic `ImpairedAudio` wrapper on both endpoints. It drops bursts 1 and 12,
damages burst 4, and duplicates burst 7 before playback. These are burst positions,
not an equal packet-loss percentage: TLS and QUIC packetize differently. Protocol
order alternates between repetitions. The experiment is local and uses the PCM
profile, not the narrowband FSK profile or a public telephone provider.

## Reproduce

```sh
uv sync --locked --extra pap --extra webrtc --extra quic
.venv/bin/python scripts/experiment_authority.py \
  --output output/authority-experiment/reproduction --repetitions 3
```

The output directory must not exist. `report.json` is checkpointed after every
completed trial. It contains the script SHA-256, starting Git revision and tracked
worktree state, dependency versions, all case outcomes, effect ledgers, per-call
handshake counters and audio fault counters. The script contains explicit expected
failures and positive controls; `all_expectations_matched` does **not** mean every
security property held.

Snapshots of calls deliberately closed for reconnect or protocol rejection have
`state: closed` and `error: ConnectionError`. These are expected teardown markers,
not failed handshakes. The other calls are sampled before their final teardown.

## Revocation schedule and controls

1. After grant consumption, the risk callback completes sign-out. The normal
   Gateway then revalidates authority before calling the handler. Expected: deny,
   zero effects.
2. The risk callback makes current authority unavailable. Expected: error, zero
   effects. This tests failure behavior, not offline availability.
3. A negative control omits only the final revalidation, then repeats sign-out
   during risk assessment. Expected: an effect with inactive authority. This
   confirms that the revocation schedule can distinguish the missing check.
4. With the normal Gateway restored, the asynchronous handler completes sign-out
   before appending its effect. Expected for the current implementation: an effect
   with inactive authority. This deliberately schedules a revocation in the
   interval between the final check and a backend effect; it measures existence
   of that window, not its probability in production.
5. After a new sign-in, the CA revokes the active voice certificate during risk
   assessment using the account-scoped public revoke API. Expected: deny, zero
   effects, despite the already established cryptographic channel.

The fourth case is a limitation of the current integration contract: the Gateway
checks authority before invoking an arbitrary asynchronous handler, and does not
make that check atomic with a later business commit. An operation that was
irrevocably authorized before revocation could instead use different semantics;
this experiment explicitly asks whether authority remains active at effect time.
The existing separate user-approved operation fixture is not exercised here, and
this result does not establish a flaw in that fixture's commit implementation.

## Scope of the conclusion

Identical outcomes would show that the tested authorization behavior comes from
the shared control policy and challenge protocol. They would not establish a new
authorization property from QUIC. Successful local re-enrollment would demonstrate
that the existing account/order/key-proof implementation works, without testing
public trust bootstrapping, issuer federation, workload attestation, transparency,
or domain/telephone-number ownership verification.

These tests cannot establish research priority or rule out a contribution under a
different threat model. They also do not measure speech-content integrity, live
relays, human usability, provider interoperability, automatic handoff, offline
revocation freshness, or a performance advantage over AuthLoop. A stronger
continuity claim would need an implemented handoff/commit mechanism and a matched
control that lacks the claimed property.
