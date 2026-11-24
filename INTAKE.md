# Intake

Warrant takes three kinds of report (DEC-258 clause 3, DEC-260, DEC-264 (5), DEC-265 (8)). Each gets a label.

| Kind | Label | Where to send it | Embargo | Triage |
|---|---|---|---|---|
| Security or privacy vulnerability | `kind:security` | GitHub private vulnerability reporting on this repository. Never a public issue. | Yes, until the fix ships | Confirmed and fixed first. The report stays private (DEC-258 (3)); its fingerprint is public from intake and attached to the fix and its remediation record (DEC-260). |
| Bug (no security or privacy impact) | `kind:bug` | A public issue | No | Reproduced, then fixed in a normal PR that links the issue. A bug found to have security impact is moved to `kind:security` and handled privately. |
| Improvement suggestion | `kind:improvement` | A public issue | No | Read as a proposal, not a defect: no fix deadline and no remediation record. Accepted ones become a candidate Law or a handoff; adoption stays with Zach (DEC-258 (4)). |

## Report fingerprint

Any report, of any kind, may carry a public fingerprint so the submitter can check it was received unchanged:

    fingerprint = SHA-256(nonce || report)

- `nonce` is 16 fresh random bytes (128 bits); `report` is the report text as UTF-8. The submitter keeps the nonce with the report.
- The fingerprint and the scheme name `sha256(nonce16||utf8(report))` are published; the nonce is not.
- The nonce is what keeps a short or templated report from being guessed by hashing candidate texts. A hash of the bare report is not accepted.
- `intake/fingerprint.py` computes and verifies it (standard library only).
