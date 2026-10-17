# Assay API Contract

All API endpoints return JSON. All responses are utf-8 encoded.

## Scan Endpoint

`GET /api/v1/scan?asset=CODE-ISSUER`

Scans an asset and returns its capability report.

### Response Headers

- `X-Assay-Undetermined`: Set to `true` when a scan is degraded due to an upstream source outage (such as failure to reach StellarExpert). When present, the response body contains `undetermined: true` and `undetermined_checks`, indicating that the source data was incomplete and the severity should be treated with caution.

### Status Codes

- `200 OK`: Successful scan (check `X-Assay-Undetermined` header or `undetermined` field for source degradation).
- `400 Bad Request`: Invalid asset code or issuer, or missing `?asset=` parameter. Also returned for an identifier naming the network's native asset — see below.
- `404 Not Found`: Asset not found on the ledger.
- `502 Bad Gateway`: Scan failed due to an underlying network or upstream error.

### The native asset

The native asset (XLM) has no issuer account, so there are no authorization
flags to read and nothing to classify. An identifier that names it — `native`
or `XLM`, in any case, with no issuer half — is answered with
`400 Bad Request` and an explicit message, never a parse error and never a
report:

```json
{ "error": "native asset has no issuer and no authorization flags: \"XLM\" cannot be scanned or attested" }
```

It is refused by design: the native asset is never scanned and never attested,
so it stays exactly what [integrating.md](integrating.md) already uses it as —
a never-attested asset the on-chain gate refuses. `GET /api/v1/history?asset=XLM`
returns the same `400` and message. A credit asset whose code merely happens
to be XLM (`XLM-G…`) is an ordinary asset and scans normally.
