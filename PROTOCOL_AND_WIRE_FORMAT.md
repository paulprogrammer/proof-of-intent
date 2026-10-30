# Protocol & Wire Format Specification

This document specifies the concrete data structures and cryptographic envelopes for the Proof-of-Intent (PoI) framework, built on standard JOSE (**RFC 7515 JWS**, **RFC 7519 JWT**, **RFC 7800 PoP `cnf`**, **RFC 8725 JWT BCP**, **RFC 8785 JCS**) and **W3C WebAuthn** primitives.

---

## 0. Parameterized Media Type Convention (`application/poi+jwt;kind=...`)

Rather than registering five separate `+jwt` media types, PoI uses a single parameterized media type **`application/poi+jwt`** with a required `kind` parameter (`kct`, `roll`, `chal`, `assert`, `rcpt`) per **RFC 6838 Section 4.3** and **RFC 7515 Section 4.1.9**:

| `kind` | HTTP `Content-Type` | JWS Protected Header `typ` | Artifact |
| :--- | :--- | :--- | :--- |
| `kct` | `application/poi+jwt;kind=kct` | `"poi+jwt;kind=kct"` | Key Certification Token (IdP -> Client) |
| `roll` | `application/poi+jwt;kind=roll` | `"poi+jwt;kind=roll"` | PoP Key Rollover Request (Client -> IdP) |
| `chal` | `application/poi+jwt;kind=chal` | `"poi+jwt;kind=chal"` | Intent Challenge Object (Service -> Client) |
| `assert` | `application/poi+jwt;kind=assert` | `"poi+jwt;kind=assert"` | Tier 1 Human Assertion JWS (Client -> Service) |
| `rcpt` | `application/poi+jwt;kind=rcpt` | `"poi+jwt;kind=rcpt"` | Countersigned Intent Receipt (Service -> Audit Log) |

---

## 1. Ephemeral Key Certificate (IdP -> Client)

At login (or upon PoP key rotation), the Frontend Signing Vault generates a non-extractable asymmetric keypair (`ES256` MTI, or `EdDSA` Ed25519) that is strictly separate from any transport-level DPoP key, and submits the public JWK to the IdP.

The IdP returns a signed JWT (`typ: "poi+jwt;kind=kct"`) conforming to **RFC 7800**:

### 1.1 Protected Header
```json
{
  "alg": "ES256",
  "typ": "poi+jwt;kind=kct",
  "kid": "idp-root-key-2026-10"
}
```

### 1.2 Payload Claims
```json
{
  "iss": "https://auth.example.com",
  "sub": "user:physician-8842",
  "aud": "https://api.example.com",
  "session_id": "sess_01JBC99281X",
  "auth_time": 1793388000,
  "iat": 1793389800,
  "nbf": 1793389800,
  "exp": 1793391000,
  "prev_jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }
  }
}
```
* **`auth_time`**: Timestamp of initial interactive user authentication (preserved across key rotations).
* **`nbf` / `exp`**: Tight validity window (e.g., 15-20 minutes, max 30 minutes) for this specific ephemeral key.
* **`prev_jkt`**: Optional RFC 7638 JWK Thumbprint of the predecessor ephemeral key (`K_(n-1)`) when issued via PoP rotation.
* **`cnf.jwk`**: The public key of the client-generated non-extractable keypair.

---

## 2. Proof-of-Possession (PoP) Key Rotation Request (Client -> IdP)

Before `K_1` expires, the client generates `K_2` and signs a rotation request (`typ: "poi+jwt;kind=roll"`) using `Priv(K_1)`. This token can be submitted to an **OAuth 2.0 Token Exchange (RFC 8693)** endpoint (`subject_token_type=urn:ietf:params:oauth:token-type:poi-roll`, `requested_token_type=urn:ietf:params:oauth:token-type:poi-kct`):

### 2.1 Protected Header
```json
{
  "alg": "ES256",
  "typ": "poi+jwt;kind=roll",
  "kcert": "<Compact-JWS-of-Current-K1-Certificate>"
}
```

### 2.2 Payload
```json
{
  "iss": "user:physician-8842",
  "aud": "https://auth.example.com/oauth/token",
  "iat": 1793390700,
  "nonce": "roll_998123a8f",
  "new_cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "1234J3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvR999",
      "y": "9999zRu9m36HLN_tue659LNpXW6pCyStikYjKIWI111"
    }
  }
}
```
The IdP verifies that `kcert` is valid and currently within `[nbf, exp]`, verifies the JWS signature using `kcert.cnf.jwk`, checks that the session has not been revoked, and issues the new certificate for `K_2`.

---

## 3. Downstream Service HITL Challenge (Service -> Client)

When an AI agent proposes a high-consequence action (or when an approver opens a queued async request), the Downstream Service returns HTTP `403 Forbidden` with a **`PoI-Challenge`** header and a signed challenge body (`Content-Type: application/poi+jwt;kind=chal`, `typ: "poi+jwt;kind=chal"`):

```json
{
  "iss": "https://rx-service.example.com",
  "challenge_id": "chal_01JBC9Z881",
  "intent_id": "intent_rx_7721",
  "iat": 1793390100,
  "nbf": 1793390100,
  "exp": 1793390400,
  "required_tier": "urn:ietf:params:oauth:poi:tier:session-pop",
  "authorization_details": {
    "type": "medication_prescription",
    "actor": "agent:clinical-copilot-v2",
    "initiated_by": "user:medical-assistant-441",
    "raw_params": {
      "patient_id": "pt_9981",
      "ndc": "00093-3109-05",
      "dose_mg": "500",
      "frequency": "TID",
      "duration_days": 7
    },
    "raw_params_hash": "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "display_facts": {
      "title": "Approve Medication Prescription",
      "fields": [
        { "label": "Patient", "value": "John Smith (DOB: 1975-04-12, MRN: 9981)" },
        { "label": "Medication", "value": "Amoxicillin 500mg Capsule" },
        { "label": "Directions", "value": "1 capsule by mouth 3 times daily for 7 days" }
      ],
      "editable_schema": {
        "dose_mg": { "type": "string", "enum": ["250", "500", "875"] },
        "duration_days": { "type": "integer", "min": 3, "max": 14 }
      }
    }
  }
}
```
* **Why `display_facts` is inside the service's signature:** Neither the AI orchestrator nor a network MITM can alter the human-readable labels shown in the Signing Vault without invalidating the Downstream Service's signature.
* **String-Encoded Fixed-Precision Numbers:** Currency amounts, interest rates, and dosages (`"500"`, `"60000.00"`, `"6.25"`) are encoded as strings so **RFC 8785 (JCS)** canonicalization produces identical digests across Python, JavaScript, Go, and Java runtimes.

---

## 4. The Proof-of-Intent Envelope (Chained Assertions)

The Proof-of-Intent Envelope (`application/poi-envelope+json`) carries the hash-linked chain of assertions (`R0 -> R1 -> ... -> Rn`). Each human step in the chain is an individually signed JWS or WebAuthn assertion committing to the prior node's hash.

### 4.1 Node Structure (`SUPERCEDE` followed by `APPROVE`)

```json
{
  "intent_id": "intent_loan_4409",
  "chain": [
    {
      "seq": 0,
      "node_type": "PROPOSAL",
      "challenge_jws": "<Compact-JWS-from-Downstream-Service>",
      "node_hash": "sha256:H0_8f992a..."
    },
    {
      "seq": 1,
      "node_type": "SUPERCEDE",
      "supercedes_node_hash": "sha256:H0_8f992a...",
      "assurance_tier": "urn:ietf:params:oauth:poi:tier:session-pop",
      "assertion_jws": "<Compact-JWS-Signed-by-Loan-Officer-K1>",
      "node_hash": "sha256:H1_3c771b..."
    },
    {
      "seq": 2,
      "node_type": "APPROVE",
      "target_node_hash": "sha256:H1_3c771b...",
      "assurance_tier": "urn:ietf:params:oauth:poi:tier:webauthn-uv",
      "assertion_jws": "<Compact-JWS-or-WebAuthn-Bundle-Signed-by-Sr-Underwriter>",
      "node_hash": "sha256:H2_9a110f..."
    }
  ]
}
```

### 4.2 Inside `assertion_jws` for Tier 1 (Ephemeral Session Key)

**Protected Header:**
```json
{
  "alg": "ES256",
  "typ": "poi+jwt;kind=assert",
  "kcert": "<Compact-JWS-of-Signer-Ephemeral-Key-Cert>"
}
```

**Payload (Example: Node 1 `SUPERCEDE`):**
```json
{
  "aud": "https://loan-service.example.com",
  "intent_id": "intent_loan_4409",
  "challenge_id": "chal_01JBC9Z881",
  "seq": 1,
  "decision": "SUPERCEDE",
  "supercedes_node_hash": "sha256:H0_8f992a...",
  "asserted_params": {
    "borrower_id": "brw_112",
    "loan_amount_usd": "60000.00",
    "interest_rate_pct": "6.25",
    "term_months": 60
  },
  "asserted_params_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "justification": "Borrower added qualified co-signer; verified combined DTI < 28%.",
  "client_iat": 1793390210
}
```

### 4.3 Inside the Proof Bundle for Tier 2 / Tier 3 (WebAuthn Biometric / Hardware Token)

When `required_tier` is `urn:ietf:params:oauth:poi:tier:webauthn-uv` or `urn:ietf:params:oauth:poi:tier:webauthn-hw`, the client passes the canonical hash of the assertion payload (`SHA-256(JCS(assertionPayload))`) as the WebAuthn `challenge`:

```javascript
const assertionBytes = new TextEncoder().encode(jcsCanonicalize(assertionPayload));
const challengeHash = await crypto.subtle.digest("SHA-256", assertionBytes);

const credential = await navigator.credentials.get({
  publicKey: {
    challenge: challengeHash,
    rpId: "example.com",
    allowCredentials: allowedCredentialIdsForTier,
    userVerification: "required"
  }
});
```

The resulting node attaches the WebAuthn response:
```json
{
  "payload": { "...canonical assertion payload including aud..." },
  "webauthn_proof": {
    "credential_id": "cred_yubikey_9912",
    "authenticator_data": "<base64url-authenticatorData>",
    "client_data_json": "<base64url-clientDataJSON>",
    "signature": "<base64url-hardware-signature>"
  }
}
```

---

## 5. Countersigned Audit Receipt (Preventing Backdated Forgeries)

Because an ephemeral key has a finite window `[nbf, exp]`, an offline auditor inspecting a record months later needs cryptographic proof that the user's signature was **received by the service while `[nbf, exp]` was still active** (preventing an attacker who compromises a key at `13:59` from backdating a signature to `13:30` next week).

Upon verifying the Proof-of-Intent Envelope, the Downstream Service immediately generates a countersigned receipt (`typ: "poi+jwt;kind=rcpt"`):

```json
{
  "iss": "https://loan-service.example.com",
  "receipt_id": "rcpt_01JBC9ZZ99",
  "intent_id": "intent_loan_4409",
  "head_node_hash": "sha256:H2_9a110f...",
  "committed_params_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "received_at": 1793390212,
  "verified_signers": [
    {
      "seq": 1,
      "sub": "user:loan-officer-102",
      "action": "SUPERCEDE",
      "assurance_tier": "urn:ietf:params:oauth:poi:tier:session-pop",
      "key_cert_nbf": 1793389800,
      "key_cert_exp": 1793391000
    },
    {
      "seq": 2,
      "sub": "user:sr-underwriter-008",
      "action": "APPROVE",
      "assurance_tier": "urn:ietf:params:oauth:poi:tier:webauthn-uv",
      "credential_id": "cred_touchid_441"
    }
  ]
}
```

---

## 6. Deterministic Verification Algorithm (Verifier SDK Checklist)

Any downstream service or audit tool verifies a Proof-of-Intent Envelope using this stateless algorithm:

1. **Enforce Bounded Chain Length (`MAX_CHAIN_LENGTH`):**
   * Confirm `2 <= length(chain) <= MAX_CHAIN_LENGTH` (default `16`) before performing any cryptographic checks.
2. **Verify Origin Proposal (`R0`):**
   * Verify `challenge_jws` has `typ: "poi+jwt;kind=chal"` and verify its signature against the Downstream Service's public key.
   * Compute `H0 = SHA-256(ASCII(challenge_jws))` and confirm `chain[0].node_hash == H0`.
3. **Walk the Chain (`i = 1 ... n`):**
   * **Linkage & Audience Check:** Confirm `chain[i].supercedes_node_hash` (or `target_node_hash`) equals `chain[i-1].node_hash`, and `assertion.aud == ico.iss`.
   * **If Tier 1 (`session-pop`):**
     1. Extract `kcert` from the JWS protected header, confirm `typ == "poi+jwt;kind=kct"`, and verify its signature against the IdP's root public key.
     2. Confirm the verification timestamp (`now` at ingestion, or `receipt.received_at` during offline audit) satisfies `kcert.nbf <= t <= kcert.exp` (within <= 60s clock skew tolerance).
     3. Confirm `assertion_jws` has `typ == "poi+jwt;kind=assert"` and verify its signature using `kcert.cnf.jwk`.
   * **If Tier 2 / Tier 3 (`webauthn-uv` / `webauthn-hw`):**
     1. Parse `client_data_json` and confirm `type == "webauthn.get"`, `origin` matches the Signing Vault origin (and when `crossOrigin == true`, `topOrigin` matches the allowlisted host application origin), and `challenge == base64url(SHA-256(JCS(canonical_payload)))`.
     2. Verify `authenticator_data` RP ID hash and confirm the `UP` (User Present) and `UV` (User Verified) flags are set.
     3. Verify `signature` against the user's registered WebAuthn public key for that tier.
   * **Hash Commitment:** Compute `H_i` over the current node and confirm `chain[i].node_hash == H_i`.
4. **Output Verified Context to Policy Engine:**
   * Emit the verified effective payload (`asserted_params` of the latest `SUPERCEDE` node at index `k_last_supercede`, or `R0.raw_params` if none) alongside the ordered list of verified signers at indices `i >= k_last_supercede`.

---

## 7. Error Taxonomy & Failure Modes

When verification or challenge evaluation fails, services return a **`PoI-Challenge: error="..."`** response header alongside an **RFC 9457 (`application/problem+json`)** body specifying the deterministic `poi_error` code and `failed_node_seq`:

```json
{
  "type": "urn:ietf:params:oauth:poi:error:kct_expired",
  "title": "Ephemeral Intent Key Certificate Expired",
  "status": 401,
  "detail": "Node seq 1 carries a kcert whose exp claim (1793391000) is earlier than server evaluation time (1793391125).",
  "poi_error": "kct_expired",
  "intent_id": "intent_loan_4409",
  "failed_node_seq": 1
}
```

### 7.1 Failure Mode Matrix (23 Total Codes: 19 Core + 4 Chained State Extension)

| `poi_error` Code | Spec | Failure Category | HTTP Status | Trigger Condition |
| :--- | :--- | :--- | :--- | :--- |
| `intent_proof_required` | Core | Step-Up / Challenge | `403` | No `PoI-Envelope` was supplied for a protected action; response includes initial `challenge_jws` (`R0`). |
| `insufficient_assurance_tier` | Core | Step-Up / Challenge | `403` | Signature is valid, but action or `SUPERCEDE` parameters require a higher tier (e.g., `webauthn-hw`). |
| `invalid_kct_signature` | Core | Cryptographic | `401` | Ephemeral Key Certificate (`kcert`) signature failed verification against the IdP public key or has invalid `typ`/`alg`. |
| `invalid_ico_signature` | Core | Cryptographic | `400` | Root challenge (`challenge_jws`) signature failed verification against the Downstream Service public key (blocks MITM/UI spoofing). |
| `invalid_assertion_signature` | Core | Cryptographic | `401` | User assertion signature failed mathematical verification against `kcert.cnf.jwk` (Tier 1) or WebAuthn credential key (Tier 2/3). |
| `audience_mismatch` | Core | Cryptographic / Binding | `401` | `assertion.aud` does not match `ico.iss` (or `kcert.aud` excludes the Resource Server), preventing cross-service replay. |
| `invalid_webauthn_attestation` | Core | Cryptographic | `401` | WebAuthn `origin`, `topOrigin`, RP ID hash, `UP`/`UV` flags, or hardware credential class failed verification. |
| `invalid_rollover_proof` | Core | Cryptographic | `401` | PoP key rotation request (`poi+jwt;kind=roll`) failed signature verification under predecessor key `K_n`. |
| `kct_not_yet_valid` | Core | Temporal (`nbf`) | `401` | Verification time `t_eval < kcert.nbf` (beyond <= 60s clock skew tolerance). |
| `kct_expired` | Core | Temporal (`exp`) | `401` | Verification time `t_eval > kcert.exp` (or expired `K_n` used to request PoP key rollover). |
| `challenge_not_yet_valid` | Core | Temporal (`nbf`) | `400` | Verification time `t_eval < ico.nbf`. |
| `challenge_expired` | Core | Temporal (`exp`) | `401` / `403` | Verification time `t_eval > ico.exp`; service may attach a fresh `challenge_jws`. |
| `session_max_age_exceeded` | Core | Temporal (`auth_time`) | `401` | `(t_eval - kcert.auth_time)` exceeds the service's `max_age` freshness policy or maximum session lifetime. |
| `session_revoked` | Core | Temporal / Session | `401` | Logical `session_id` was terminated or logged out prior to `kcert.exp`. |
| `challenge_replayed` | Core | Replay | `409` | `challenge_id` or rollover `nonce` has already been consumed. |
| `malformed_poi_envelope` | Core | Syntax / Format | `400` | Envelope JSON/JWS is unparseable, missing required claims, has invalid `typ;kind`, or exceeds `MAX_CHAIN_LENGTH`. |
| `chain_continuity_broken` | Core | Chain Integrity | `422` | `supercedes_node_hash` or `target_node_hash` does not match `chain[i-1].node_hash`, or `seq` is out of order. |
| `params_hash_mismatch` | Core | Payload Integrity | `422` | Canonical `SHA-256(JCS(params))` does not match committed `raw_params_hash` or `asserted_params_hash` (tampering detected). |
| `intent_rejected` | Core | Terminal Decision | `422` | Chain ends in a signed `REJECT` assertion; execution is permanently aborted. |
| `authority_escalation_required` | Chained | Escalation | `202` / `403` | `SUPERCEDE` assertion (`Rk`) is valid, but exceeds the signer's organizational policy limit; requires next-line approval (`R_(k+1)`). |
| `stale_head_conflict` | Chained | Concurrency / CAS | `409` | A concurrent signer advanced `head_node_hash` from `Hk` to `H_(k+1)` while the user was signing against `Hk`; response includes updated chain. |
| `intent_already_finalized` | Chained | Concurrency / Terminal | `409` | A concurrent signer's assertion already transitioned the intent to a terminal executed or rejected state (`CIR` issued) before this assertion arrived. |
| `context_state_drifted` | Chained | State / TOCTOU | `409` | Underlying domain record changed between challenge issuance (`context_state_hash`) and PoIE submission. |
