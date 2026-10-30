# OpenAVT research paper

**Title:** OpenAVT: Binding Delegated Agent Authority to Voice Channels

This is a research draft, with an implemented prototype and a prospective
evaluation plan. It is not a submitted or accepted paper. The prototype results
are local feasibility observations, not a completed real-world security study.

**Novelty assessment:** the subsequent [October 30 research audit](research/novelty-audit-2026-10-30.md)
identifies additional close work on secure telephony, automated certificate issuance
and agent authorization. It does not yet establish a strong novelty claim for the
current implementation. Consult the audit before treating the draft's positioning
as submission-ready.

The draft covers personal agents and multimodal/physical AI motivation; the
Pindrop field report; when existing APIs, protocols, media security and detection
are sufficient or complementary; technical challenges; OpenAVT design and trust
boundaries; current evidence; evaluation methodology; related work; discussion;
and Ethics/Open Science appendices.

## Sources and build

- `main.tex` and `sections/`: editable LaTeX manuscript.
- `references.bib`: verified primary-source references and the vendor field report.
- `usenix.sty`: unmodified style file from the official [USENIX Security 2027 template archive](https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip), retrieved October 30, 2026.
- `scripts/extract_results.py`: regenerates `artifacts/measurements.tex` from
  `../docs/quic-verification.json`; no synthetic measurements are generated.
- `openavt.pdf`: compiled draft, supplied after visual inspection.

With [Tectonic](https://tectonic-typesetting.github.io/) installed:

```sh
cd paper
make pdf
```

Tectonic downloads needed TeX packages on the first build and runs bibliography
passes automatically. The output is `../output/pdf/main.pdf`. XeTeX/Tectonic lacks
microtype's pdfTeX word-spacing and kerning features, so `main.tex` conditionally disables
those unsupported features, without changing margins or shrinking type. For the official
template's pdfTeX rendering, use the commands below. Under XeTeX the preamble also
uses native `hyperref` URL handling instead of `breakurl`'s PostScript hooks;
the vendored style file itself is unchanged.

```sh
python3 paper/scripts/extract_results.py
cd paper
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

The generated table contains four single-call observations. It deliberately
does not compute a median, confidence interval or improvement over the historical
TLS measurements. The implemented baseline is commit
`033f8bfbc69c4bfa44163f8fa4a680a004400f75` on `feat/quic-over-voice`.

## Venue positioning

The current manuscript uses the official USENIX style, letter paper, two columns
and 10-point text. The [USENIX Security 2027 CFP](https://www.usenix.org/conference/usenixsecurity27/call-for-papers)
allows up to 13 body pages and requires an Open Science appendix; an Ethics
appendix is encouraged. This draft includes both appendices. It retains the
template defaults and does not compress spacing to meet a limit.

For [SIGCOMM 2027](https://conferences.sigcomm.org/sigcomm/2027/submission/), migrate
to the venue-linked ACM template, keep the body within 12 pages, use its required
anonymous submission-number/page-count author block, and emphasize the controlled
transport/adaptation comparison. This USENIX layout is not a SIGCOMM-format submission.

Before submission, the authors must supply accurate authorship, choose a venue,
complete the research evaluation, audit references and claims, check the latest
rules, prepare a stable anonymous artifact deposit, and apply the venue's
anonymity and AI-assistance disclosure policies. No submission number, reviewer
artifact URL, real-user consent study, formal proof, or external-provider
validation is asserted in the manuscript.

## Evidence that remains to be collected

1. Matched TLS/QUIC/selective-repeat comparisons across rates, losses and delays.
2. Real Internet/provider and microphone paths with explicitly logged codecs and processing.
3. End-to-end attack trials measuring backend effects and leaks through every enabled output.
4. Relay, handoff, shared-key, concurrent-call and commit-time revocation analysis.
5. Statistical replication, resource/fairness measurements and audibility/usability studies.
6. Independent review of the private aioquic mutual-authentication hooks.

The public PAP specification now resolves to draft 0.3. The repository adapter
targets its earlier draft 0.1 profile. The paper distinguishes those versions
and does not claim current-draft conformance or external interoperability.
