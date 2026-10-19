# Evidence preimage conformance suite

A language-neutral set of test cases for the canonical `evidence_hash`
preimage, specified by the ABNF grammar in
[`docs/contract-interface.md`](../docs/contract-interface.md#formal-grammar-abnf).
Any reimplementation — any language, no Go involved — can validate itself
against this directory alone.

## Layout

- `cases.json` — one JSON object per case: `name`, the grammar rules the
  case exercises (`covers`), an `input` report in the scanner's report JSON
  shape, the expected `preimage` bytes (JSON-escaped: `\n` for LF, `\t` for
  HTAB), and the expected `digest` (lowercase hex SHA-256 of the preimage
  bytes; this is the `evidence_hash`).

## Running the suite

- **Go (this repo, runs in CI):** `go test ./internal/attest/ -run Conformance -v`.
  `internal/attest/conformance_test.go` replays every case through
  `attest.FromReport` and also re-hashes the expected preimage against the
  expected digest, so a case cannot pin bytes its own digest disagrees with.
- **Python (this repo, runs in CI):** `make test-preimage` drives
  [`scripts/preimage_encoder.py`](../scripts/preimage_encoder.py), an
  independent implementation written from the specification alone. It runs
  the conformance cases together with every committed vector and every
  `internal/mechanics/testdata` subject, comparing its preimage bytes and
  digests against the Go encoder's.
- **Anything else:** for each case, parse `input` as a report, render the
  preimage per the grammar, and compare it byte-for-byte with `preimage`;
  then check `SHA-256(preimage) == digest`. Nothing in this directory is
  Go-specific.

The Go test additionally fails if the grammar in the spec gains a rule no
case declares in `covers`, so a new rule cannot be documented without a
case that pins it.

## Input report shape

`input` is the report JSON the scanner prints (`mechanics.Report`), limited
to the fields the encoding reads:

- `asset` (`code`, `issuer`), `severity`, `base_severity` — severity is the
  level *name* (`clear`/`low`/`medium`/`high`/`critical`); the preimage
  renders its numeric bit value.
- `escalated`, `accountability` (`unknown`/`unverified`/`verified`).
- `mechanics` — an array of mechanic *names* (`auth_required`,
  `auth_revocable`, `auth_clawback_enabled`, `auth_immutable`,
  `domain_unverified`, `blocklisted`, `trustline_clawback_enabled`,
  `trustline_deauthorized`); the preimage renders the OR of their bit
  positions (the ABI table in the spec) as a decimal integer.
- `checks` — the bound check set, optionally present. The encoder sorts it.
- `network` — the full network passphrase, optionally present.
- `scanner_bound` — opt-in to the scanner-identity encoding; see below.
- `evidence` — `source`, `url`, `claim` per item. Order in the input is
  irrelevant: the encoding sorts the rendered lines bytewise. Timestamps
  (`retrieved_at`) are deliberately excluded from the hash and omitted here.

Fields the encoding does not read (findings, timestamps, state,
undetermined flags) are omitted; an input carrying `undetermined: true` or
a stale state is not attestable and no case uses one.

## The `scanner_identity` field

A case whose input sets `scanner_bound` also carries a top-level
`scanner_identity`: the identity value the scanner line must render. The
Go test assigns it to `attest.ScannerIdentity` for the duration of the case
and restores it afterwards, because that value is build-dependent
(`vX.Y.Z` from the module build info, or `devel`). A reimplementation
should render exactly the identity the case names; a real scanner uses its
own.

## Known divergences the suite deliberately pins

This is a current-implementation divergence, annotated in the grammar and in
the affected cases:

1. **Ambiguous `v3` tag
   ([#270](https://github.com/use-assay/Assay/issues/270)).**
   One tag covers scanner-only, network-only, and both. Both layouts appear
   as cases, each pinned to its bytes; #270's disambiguation will split the
   grammar rule and update these cases deliberately. The empty-`checks`-line
   divergence ([#269](https://github.com/use-assay/Assay/issues/269)) is
   fixed: v1 bytes have no `checks` line, and the cases pin that.

## Adding a case

Add the JSON object and list every grammar rule it is the first or best
exercise of in `covers`. The coverage test keeps you honest: the grammar
grows, the cases grow with it.
