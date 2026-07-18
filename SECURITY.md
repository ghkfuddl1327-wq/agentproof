# Security Policy

## Reporting a vulnerability

If you find a security issue in `agentproof-scan`, please open a GitHub issue
describing the problem, or contact the maintainers privately before public
disclosure where the issue is sensitive.

---

## Why this repository contains credential-shaped strings

`agentproof-scan` is a scanner that detects secret/credential leakage from AI
agents. To prove the detector fires, the test corpus and the positive-control
adapters embed **credential-shaped fixture strings** — for example a
`sk_live_...` Stripe shape, a `-----BEGIN RSA PRIVATE KEY-----` block, and a
three-segment JWT. GitHub secret scanning / push protection will flag these on
push. They are flagged **because they are shaped like real secrets — which is
the whole point of a leak-detector fixture.**

Every such string in this repository is a **verified synthetic canary**: a
non-functional value that matches a provider's *format* but authenticates
against *nothing*. The primary fixture set lives in
[`agentproof_scan/adapters/simple_chatbot_multitype_canary.py`](agentproof_scan/adapters/simple_chatbot_multitype_canary.py)
(nine families: `stripe`, `slack`, `github_pat`, `jwt`, `pem`, `sendgrid`,
`gcp`, `npm`, `twilio`).

### Provenance

The nine fixture values were generated deterministically with
`random.Random(20260715)` and are recorded verbatim in source, with an
in-file comment marking them as shape-only and non-usable. The seed is
recorded as generation provenance — the "this is fake" marker lives in the
code comment and in this document, **not in the value itself** (embedding a
placeholder keyword would defeat the detector's entropy gate).

### How a value is verified synthetic

Verification is **structural** — it proves each value is non-functional
without ever transmitting it to a provider. We deliberately do *not* validate a
fixture against a live provider API; that would mean sending a credential-shaped
string off-box, which is exactly what a leak-scanner must never do. The checks
are reproducible from the committed source with the standard library plus
`cryptography`:

1. **JWT header does not decode to JSON.** The first segment of the fixture JWT
   base64url-decodes to arbitrary bytes, not a `{"alg":...}` header object. A
   real JWT header is well-formed JSON; this one is not, so no library will
   treat it as a token.
2. **PEM block does not parse as a private key.** The `BEGIN RSA PRIVATE KEY`
   body is random base64, not valid DER/ASN.1. `cryptography`'s
   `load_pem_private_key` raises `ValueError` on it — there is no key material.
3. **Detector classification without live authentication.** Each value matches
   exactly one provider regex in `scan.detect_secrets` and passes
   `scan.is_placeholder(...) == False` (high entropy, no placeholder keyword) —
   confirming it is a genuine positive control for the detector, not a dummy the
   entropy gate would silently drop.

Checks (1)–(3) run entirely offline against the committed source. They
establish *non-functionality by construction*, which is the property that
matters for push-protection review.

> Provenance note: the `random.Random(20260715)` seed is recorded as the
> generation origin, but the generator script that reproduces these exact bytes
> is **not** committed, so a byte-for-byte "regenerate from seed" reproduction
> is not currently available. The verification of record is the structural
> proof above (non-JSON header, unparseable PEM, detector-classified,
> non-placeholder), which does not depend on trusting a generator.

---

## Push-protection unblocks

When GitHub push protection blocks a push on one of these fixtures, an unblock
is legitimate **only after** the value has been verified synthetic by the
structural checks above. The verification is the justification; the unblock is
downstream of it.

**Principle — not a procedure:**

- Only a **verified-synthetic** value is eligible to be unblocked. The evidence
  is the structural proof, recorded and repeatable.
- An unblock granted **without** that verification is a discipline violation,
  regardless of intent or how confident the author feels.
- Applying the same unblock to an **unverified** value — or to a value that
  fails any structural check — is not a fixture allowance; **that is bypassing
  secret scanning.** The allowance exists because the value is provably fake. It
  does not transfer to values that have not been proven fake.

In short: the unblock rides on the proof. No proof, no unblock. This section
states the boundary as a rule so it is auditable; it is deliberately not a
copy-paste bypass recipe.
