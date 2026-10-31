# Authority experiment: measured results, October 31, 2026

All 12 completed trials produced the same case outcomes: 3 repetitions for each
of TLS/QUIC and clean/impaired audio. There were 60 fresh audio calls and 264
case observations. All 156 denial/error/protocol-rejection cases produced zero
handler effects. Valid requests produced 96 effects. The scheduled revocation
after the final check produced 12 effects with inactive business authority;
the deliberate no-revalidation control produced another 12 such effects.
The latter 24 effects are observed limitations/controls, not security successes.

The outcome vector was identical between the two transports. This comparison
did not demonstrate an additional authorization property from QUIC. Both
transports recovered from the injected audio faults. These observations isolate
a shared backend check/commit boundary rather than establish a new mechanism.

See the [experiment method and reproduction command](../authority-experiment.md)
for the threat model, schedules, baseline, and limits. The raw compressed
[report](authority-2026-10-31.json.gz) includes every case, effect ledger,
handshake summary, dependency version and audio impairment counter.

## Outcomes

Each row occurred 12 times. Entries below are the observed result and effect
counts **per trial**, identical across all four conditions. `Inactive` means
business-session authority was inactive when the synthetic effect was appended.

| Case | Result | Effects | Inactive |
| --- | --- | ---: | ---: |
| `valid_call_a` | allowed | 1 | 0 |
| `valid_second_call_same_key` | allowed | 1 | 0 |
| `concurrent_legitimate_requests` | allowed | 2 | 0 |
| `arguments_substitution` | denied | 0 | 0 |
| `action_substitution` | denied | 0 | 0 |
| `resource_substitution` | denied | 0 | 0 |
| `customer_substitution` | denied | 0 | 0 |
| `request_id_substitution` | denied | 0 | 0 |
| `consumed_grant_replay` | denied | 0 | 0 |
| `same_key_cross_call_grant` | denied | 0 | 0 |
| `same_key_exact_transplant` | protocol_rejected | 0 | 0 |
| `original_call_after_transplant` | allowed | 1 | 0 |
| `reconnect_old_transaction` | protocol_rejected | 0 | 0 |
| `reconnect_fresh_authorization` | allowed | 1 | 0 |
| `rotated_key_old_grant` | denied | 0 | 0 |
| `old_key_still_active` | allowed | 1 | 0 |
| `rotated_key_fresh_authorization` | allowed | 1 | 0 |
| `signout_during_risk` | denied | 0 | 0 |
| `authority_outage_during_risk` | error | 0 | 0 |
| `ablation_omit_revalidation` | allowed | 1 | 1 |
| `revocation_after_final_check` | allowed | 1 | 1 |
| `certificate_revocation_during_risk` | denied | 0 | 0 |

## Descriptive timings

Handshake measurements run from starting the inner protected channel until the
client reports mutual authentication complete, excluding SDP/ICE setup and HTTPS
enrollment. There are 15 client handshake observations per condition, clustered
in 3 trials; they are not 15 independently randomized network paths. Workload
elapsed time includes enrollment, all five calls and all 22 cases in each trial.

| Transport | Audio faults | Handshake median (s) | Range (s) | Workload median (s) |
| --- | --- | ---: | ---: | ---: |
| tls | clean | 0.584 | 0.562–0.595 | 15.010 |
| tls | injected | 3.741 | 3.738–3.744 | 35.332 |
| quic | clean | 0.685 | 0.646–0.694 | 16.111 |
| quic | injected | 3.684 | 3.664–3.689 | 46.351 |

This small local workload does not establish a general speed advantage for
either protocol. The burst-index fault pattern is shared, but the packet loss
percentage and lost byte counts are not matched across different packetizations.
No narrowband, Internet/provider, speech, automatic-handoff, or independent
certificate-infrastructure result is inferred.

## Evidence integrity

The run began from the revision below with the experiment script staged; the
script hash identifies the exact experimental code. Later documentation changes
do not affect that hash. No credentials or protected request contents are stored
in the report. Closed-call `ConnectionError` markers are deliberate teardown.

- Starting Git revision: `1fec8284f44ff1b3b4b804e591a976732f46f305`.
- Script SHA-256: `2afffd8d4dc325341ad1576fbdb14a1d52f32fd040c9444f75b089cc19a81dfc`.
- Uncompressed report SHA-256: `3062903937d41e4e01eaafdc7c4f686f42f445851ef44ac5c026162628ac07c3`.
- Gzip report SHA-256: `92cd9dba86d5912ab1e90154b382ce61de08887ad2aaf2412798921a75bdf746`.

To inspect the full report:

```sh
python3 - <<'PYREPORT'
import gzip, json
from pathlib import Path
p = Path("docs/experiments/authority-2026-10-31.json.gz")
print(json.dumps(json.loads(gzip.decompress(p.read_bytes())), indent=2))
PYREPORT
```
