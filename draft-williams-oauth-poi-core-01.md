---
title: "Cryptographic Proof-of-Intent (PoI) Core Protocol for Human-in-the-Loop (HITL) Step-Up Authorization"
abbrev: "Proof-of-Intent (PoI) Core"
docname: draft-williams-oauth-poi-core-01
category: std
ipr: trust200902
submissionType: IETF
area: Security
wg: Web Authorization Protocol (oauth)
kw:
  - OAuth
  - Proof-of-Intent
  - Human-in-the-Loop
  - AI Agents
  - Step-Up Authentication
  - Mandrel

author:
  - ins: P. C. Williams
    name: Paul Charles Williams
    org: Barefoot Coders, LLC
    abbrev: Barefoot Coders
    email: paul@barefootcoders.com
    uri: https://mandrelproject.ai

normative:
  RFC2119:
  RFC6234:
  RFC6749:
  RFC6838:
  RFC7515:
  RFC7517:
  RFC7518:
  RFC7519:
  RFC7638:
  RFC7800:
  RFC8174:
  RFC8259:
  RFC8693:
  RFC8725:
  RFC8785:
  RFC9110:
  RFC9396:
  RFC9449:
  RFC9457:
  RFC9470:
  WebAuthn:
    title: "Web Authentication: An API for accessing Public Key Credentials Level 3"
    author:
      - ins: J. Hodges
      - ins: M. Jones
      - ins: R. Lindemann
      - ins: E. Lundberg
    date: 2024
    target: https://www.w3.org/TR/webauthn-3/

informative:
  POI-CHAINED:
    title: "Proof-of-Intent (PoI) Chained State, Multi-Party Escalation, and Concurrency Extension"
    author:
      - ins: P. C. Williams
        name: Paul Charles Williams
        org: Barefoot Coders, LLC
    date: 2026-11
    seriesinfo:
      Internet-Draft: draft-williams-oauth-poi-chained-state-00
  PSEA:
    title: "PSEA Token Profile: An EAT Profile for Action-Bound, User-Verification-Gated Transaction-Confirmation Evidence"
    author:
      - ins: M. K. Yossif
        name: Mohamad Khalil Yossif
        org: Yuthent
    date: 2026-10-08
    seriesinfo:
      Internet-Draft: draft-yossif-psea-03
    target: https://datatracker.ietf.org/doc/draft-yossif-psea/
  EP-RECEIPTS:
    title: "Authorization Receipts for High-Risk Agent Actions"
    author:
      - ins: I. Schrock
        name: Iman Schrock
        org: EMILIA Protocol, Inc.
    date: 2026-09-11
    seriesinfo:
      Internet-Draft: draft-schrock-ep-authorization-receipts-13
    target: https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/
  RFC6755:
  RFC7942:
  RFC8126:
  RFC9943:

--- abstract

AI agents and workflow orchestrators call high-consequence APIs on behalf of people. Bearer tokens and transport-level proof-of-possession show which client made a call. They do not show that a person approved the specific parameters of that call, and redirect-based step-up is too slow for frequent approvals.

This document specifies the Proof-of-Intent (PoI) Core protocol. A Resource Server signs a challenge that binds the exact canonical parameters (RFC 8785) to human-readable facts. The person's client answers with a signed decision (APPROVE, REJECT, or SUPERCEDE with new parameters) using a session key certified by the Authorization Server (RFC 7800) or a WebAuthn or PSEA authenticator. The Resource Server verifies the evidence without a call to the Authorization Server, admits each approval once, and issues a signed receipt.

Multi-approver chains, escalation, and concurrency are specified in draft-williams-oauth-poi-chained-state-00.

--- middle

# Introduction

## Problem Statement

An agent acting for an authenticated user calls tools and APIs on Resource Servers (RS). OAuth 2.0 ({{RFC6749}}) and DPoP ({{RFC9449}}) authenticate the client or session. They do not prove that a person approved the parameters of a specific call. Three problems follow:

1. **Confused deputy:** A prompt-injected or faulty agent with a valid token can call a privileged endpoint with parameters nobody approved.
2. **Prompt misrepresentation:** If the agent writes the approval prompt and sends raw identifiers (UUIDs, drug codes) to the RS, the person can approve text that does not match the parameters.
3. **Round-trip cost:** Rich Authorization Requests ({{RFC9396}}) with step-up ({{RFC9470}}) require an Authorization Server round-trip or an out-of-band prompt per transaction.

## Design Goals and Scope of PoI Core

PoI Core covers one proposal and one human decision (`[R0, R1]`). Verifying the evidence is stateless given trusted keys and, for Tier 2 and Tier 3, the signer's enrollment record. Admitting it is stateful: the RS records each challenge as consumed, so an approval authorizes at most one execution (Section 7.1).

* **Tier 1 without round-trips:** At login the client generates a non-extractable key that the Authorization Server certifies ({{RFC7800}}). A Tier 1 approval is one click in the client, with no Authorization Server call.
* **Tiers by consequence:** The RS sets the required tier per action: Tier 1 (session key), Tier 2 (user-verified authenticator via {{WebAuthn}} or {{PSEA}}), or Tier 3 (cross-platform hardware authenticator).
* **Edits within authority (`SUPERCEDE`):** A person who changes the proposed parameters submits `R1` as a `SUPERCEDE` carrying the new parameters.
* **Chains elsewhere:** Escalation (`R0 -> R1 -> R2`), escrow, and concurrent approvers are in {{POI-CHAINED}}.


# Conventions and Terminology

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

## Terminology

* **Ephemeral Intent Key (EIK):** A short-lived, non-extractable key pair in the client's Signing Vault, used only to sign Tier 1 decisions.
* **Key Certification Token (KCT):** A JWT ({{RFC7519}}) from the Authorization Server whose {{RFC7800}} `cnf` claim binds the user (`sub`), the authentication time (`auth_time`), and a validity window (`nbf`, `exp`) to an EIK public key.
* **Signing Vault:** An isolated client context (a cross-origin iframe or a native secure enclave) that holds the EIK, verifies RS challenges, renders display facts, and signs decisions.
* **Intent Challenge Object (ICO):** A JWS ({{RFC7515}}) from the RS that binds the canonical hash of the proposed parameters, the display facts, and the required tier.
* **Proof-of-Intent Envelope (PoIE):** A JSON object carrying a hash-linked chain of nodes. In PoI Core: the RS proposal (`R0`) and the human decision (`R1`: `APPROVE`, `REJECT`, or `SUPERCEDE`).
* **Countersigned Intent Receipt (CIR):** A signed, timestamped receipt the RS issues when it admits a PoIE. It supports offline audit after the EIK expires. It records admission only (Section 7.2).

## Parameterized Media Type Conventions (`application/poi+jwt;kind=...`)

To type every JWT ({{RFC8725}} Section 3.11) with one registration, this document defines `application/poi+jwt` ({{RFC6838}} Section 4.3) with a required `kind` parameter:

| `kind` Parameter | HTTP `Content-Type` Header | JWS `typ` Header Parameter | Artifact Description |
| :--- | :--- | :--- | :--- |
| `kct` | `application/poi+jwt;kind=kct` | `"poi+jwt;kind=kct"` | Key Certification Token (Section 4.2) |
| `roll` | `application/poi+jwt;kind=roll` | `"poi+jwt;kind=roll"` | PoP Key Rollover Request (Section 4.3) |
| `chal` | `application/poi+jwt;kind=chal` | `"poi+jwt;kind=chal"` | Intent Challenge Object (Section 5.2) |
| `assert` | `application/poi+jwt;kind=assert` | `"poi+jwt;kind=assert"` | Tier 1 Human Assertion JWS (Section 6.3.3.1) |
| `rcpt` | `application/poi+jwt;kind=rcpt` | `"poi+jwt;kind=rcpt"` | Countersigned Intent Receipt (Section 7.2) |

Per {{RFC7515}} Section 4.1.9, senders SHOULD omit the `"application/"` prefix in `typ`. Verifiers MUST treat `"poi+jwt;kind=<val>"` and `"application/poi+jwt;kind=<val>"` as equivalent (case-insensitive, optional whitespace after `;`), and MUST reject a token whose `kind` does not match the protocol step.


# Protocol Architecture and Overview

## Architectural Topology

~~~text
+-----------------+      (1) Auth + Pub(EIK)     +-----------------+
|                 | ---------------------------> |                 |
| Client Signing  | <--------------------------- |  Authorization  |
| Vault(Frontend) |      (2) Signed KCT          |   Server(IdP)   |
|                 |   [nbf, exp, cnf: Pub(EIK)]  |                 |
+-----------------+                              +-----------------+
   ^           |
   | (5)Verify | (6) Signed PoIE
   |    ICO &  |     ([R0, R1])
   |    Render v
+-----------------+      (3) Propose Action      +-----------------+
|                 | ---------------------------> |                 |
| AI Orchestrator/| <--------------------------- | Resource Server |
| Intermediary    |      (4) HTTP 403 + ICO (R0) | (Loan / Rx Svc) |
|                 | ---------------------------> |                 |
+-----------------+      (7) Submit PoIE [R0, R1]+-----------------+
                         (or direct Vault->RS)            |
                                                          v
                                                 +-----------------+
                                                 |Orthogonal Policy|
                                                 |Engine/Audit Log |
                                                 +-----------------+
~~~

## Orthogonality to Policy Enforcement

PoI proves human intent. It does not decide policy.

1. **PoI verification** decides whether `R1` over `R0` was produced by the claimed subject, inside a valid key window, for this audience, at the required tier, over the exact canonical parameters.
2. **Policy** uses the verified result to apply organization rules such as amount thresholds, prescribing authority, or roles.


# Ephemeral Intent Key (EIK) Lifecycle

## Client-Side Non-Extractable Key Generation and Separation from Transport DPoP

The Signing Vault MUST generate the EIK locally. Implementations MUST support `ES256` (ECDSA P-256 with SHA-256) and SHOULD support `EdDSA` (Ed25519) ({{RFC7518}}).

1. The private key MUST NOT be generated by or sent to the Authorization Server or any backend.
2. With the Web Cryptography API, the key pair MUST be generated with `extractable: false`, and the private key's usages MUST be limited to `["sign"]` (the public key may allow `["verify"]`).
3. The private key handle SHOULD stay in memory inside a cross-origin isolated Signing Vault and MUST NOT be written to persistent storage.
4. **Separate from DPoP keys ({{RFC9449}}):** A client MUST NOT use its DPoP key as the EIK. DPoP keys sign background requests without a person present. The EIK MUST only be used in the Signing Vault after an explicit user gesture.

## Key Certification Token (KCT) via RFC 7800

At login, the client sends the EIK public key as a JWK ({{RFC7517}}). After authenticating the user, the Authorization Server issues a KCT, a signed JWT ({{RFC7519}}):

* **JWS Protected Header:**
  * `alg`: Asymmetric algorithm (`ES256` MTI). `none` and MAC algorithms (`HS256`) MUST NOT be used.
  * `typ`: MUST be `"poi+jwt;kind=kct"` (or `"application/poi+jwt;kind=kct"`).
  * `kid`: The Authorization Server's signing key identifier.
* **JWT Payload Claims:**
  * `iss` (REQUIRED): Authorization Server issuer URI.
  * `sub` (REQUIRED): The authenticated user.
  * `aud` (OPTIONAL): Resource Server trust domain(s) that may rely on this KCT.
  * `session_id` (REQUIRED): The authentication session.
  * `auth_time` (REQUIRED): NumericDate ({{RFC7519}}) of the user's last interactive authentication.
  * `iat` (REQUIRED): Issuance time.
  * `nbf` (OPTIONAL): Time before which the EIK MUST NOT be accepted. Defaults to `iat`.
  * `exp` (REQUIRED): Time after which the EIK MUST NOT be accepted. `(exp - iat)` is RECOMMENDED not to exceed 1800 seconds for interactive sessions.
  * `cnf` (REQUIRED): {{RFC7800}} confirmation with a `jwk` member holding the EIK public key (no private parameters).
  * `prev_jkt` (OPTIONAL): {{RFC7638}} thumbprint of the previous EIK in the session, set on rotation (Section 4.3).

*Non-normative example of a KCT payload:*

~~~json
{
  "iss": "https://idp.example.org",
  "sub": "user:dr-jane-doe-992",
  "aud": "https://api.example.org",
  "session_id": "sess_88192a",
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
~~~

## Proof-of-Possession (PoP) Key Chaining Rotation and RFC 8693 Binding

Sessions longer than one KCT window rotate keys instead of using bearer refresh tokens:

1. Before the active key `K_n` expires, the Signing Vault generates a new non-extractable key `K_(n+1)`.
2. It signs a rollover request (`typ: "poi+jwt;kind=roll"`) with `K_n`:
   * The protected header MUST include `kcert`: the active KCT for `K_n`.
   * The payload MUST include `iss` (equal to `kcert.sub`), `aud` (the Authorization Server issuer or token endpoint), `iat`, a unique `nonce`, and `new_cnf.jwk` (the `K_(n+1)` public key).
3. **Token Exchange ({{RFC8693}}):** The client MAY send the request to the token endpoint:
   * `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`
   * `subject_token`: `<Compact-JWS-of-Rollover-Request>`
   * `subject_token_type`: `urn:ietf:params:oauth:token-type:poi-roll`
   * `requested_token_type`: `urn:ietf:params:oauth:token-type:poi-kct`
4. The Authorization Server MUST verify that:
   * the `kcert` signature is valid and its `[nbf, exp]` window covers the current time;
   * the rollover signature verifies under `kcert.cnf.jwk` and `aud` names the Authorization Server; and
   * the session in `kcert.session_id` is not revoked and has not exceeded its maximum lifetime since `kcert.auth_time`.
5. The Authorization Server then issues a KCT for `K_(n+1)` with the original `auth_time` and `prev_jkt` set to the {{RFC7638}} thumbprint of `K_n`.
6. On receiving the new KCT, the Signing Vault MUST destroy the `K_n` handle.


# Resource Server Intent Challenge

## HTTP 403 Step-Up Challenge Signaling (`PoI-Challenge`)

Requests to a Resource Server already carry `Authorization: Bearer` or `Authorization: DPoP` ({{RFC9110}} Section 11.6.1), so PoI uses its own header instead of an HTTP authentication scheme.

When a request needs proof of intent, the RS MUST respond with `403 Forbidden`, a `PoI-Challenge` header, and an `application/poi+jwt;kind=chal` body:

~~~http
HTTP/1.1 403 Forbidden
PoI-Challenge: error="intent_proof_required",
  intent_id="intent_rx_7721",
  required_tier="urn:ietf:params:oauth:poi:tier:session-pop"
Content-Type: application/poi+jwt;kind=chal

<Compact-JWS-of-Intent-Challenge-Object>
~~~

## Intent Challenge Object (ICO) Format

The body is an ICO: a JWS (`typ: "poi+jwt;kind=chal"`) signed by the RS.

* **JWS Protected Header:**
  * `alg`: The RS signing algorithm (`ES256` MTI).
  * `typ`: MUST be `"poi+jwt;kind=chal"` (or `"application/poi+jwt;kind=chal"`).
  * `kid`: The RS key identifier.
* **ICO Payload Claims:**
  * `iss` (REQUIRED): The RS identifier URI.
  * `challenge_id` (REQUIRED): A random identifier for this challenge.
  * `intent_id` (REQUIRED): The business occurrence. A new challenge for the same occurrence (after expiry, or during recovery) MUST reuse the `intent_id` with a new `challenge_id`. Section 9.4 depends on this.
  * `iat`, `exp` (REQUIRED): Issuance and expiry. `nbf` (OPTIONAL) defaults to `iat`. `(exp - iat)` SHOULD NOT exceed 300 seconds.
  * `required_tier` (REQUIRED): The minimum tier URN (Section 6.3).
  * `authorization_details` (REQUIRED): A {{RFC9396}} object with these PoI members:
    * `type`: The action type.
    * `actor`: The proposing agent or client.
    * `raw_params`: The executable parameters, as a JSON object.
    * `raw_params_hash`: The digest of `raw_params` (Section 5.3).
    * `display_facts`: What the person sees, resolved by the RS from `raw_params` (for example, account names instead of IDs). A JSON object with a `title` string and a `fields` array of `{label, value}` strings in display order. It MAY include `editable_schema`, a JSON object describing which `raw_params` the signer may change in a `SUPERCEDE` and within what bounds; the Signing Vault builds its edit form from it, and the RS MUST reject a `SUPERCEDE` whose `asserted_params` fall outside it. The Signing Vault MUST render the title and every field in order before signing, and MUST refuse to sign if `display_facts` does not conform.
    * **Coverage:** Every member of `raw_params` is covered by `raw_params_hash` and reaches execution, so the RS MUST represent every member of `raw_params` in `fields`. It MUST NOT issue a challenge whose `raw_params` hold a member the signer is not shown; a parameter that should not be displayed does not belong in `raw_params`.
    * **Display safety:** Labels and values often derive from input the proposing agent controls. The RS MUST NOT issue a challenge in which a label or value contains control or format characters (line breaks, bidirectional controls, zero-width characters), or in which two labels read the same.

## Canonical Parameter Hashing and Numeric Precision via RFC 8785 (JCS)

To hash a parameter object (`raw_params`, `asserted_params`) or an assertion payload, implementations MUST:

1. Serialize it with the JSON Canonicalization Scheme ({{RFC8785}}).
2. Compute SHA-256 ({{RFC6234}}) over the canonical UTF-8 bytes.
3. Format the digest as `"sha256:"` followed by 64 lowercase hex characters. Profiles that carry another encoding (such as base64 in {{PSEA}}) MUST be compared on the decoded 32 octets.
4. **Numbers:** Fixed-precision values (amounts, rates, dosages) SHOULD be JSON strings (`"60000.00"`) to avoid floating-point differences across runtimes. Verifiers MUST hash the parsed JSON from the JWS payload, before mapping it into types that could drop unknown or null fields.


# Proof-of-Intent Envelope (PoIE) Core Profile

## Two-Node Core Envelope (`[R0, R1]`) and Header Size Considerations

A PoIE (`application/poi-envelope+json`) in PoI Core has a two-node `chain`:

* **`R0` (`PROPOSAL`):** Carries the ICO. `node_hash` (`H0`) is `SHA-256(ASCII(challenge_jws))`, formatted as in Section 5.3. Profiles that bind a node hash (such as the PSEA `eat_nonce`, Section 6.3.3.2) use its 32 decoded octets.
  * **Detached mode:** Reverse proxies often limit headers to 4 to 8 KB. When the envelope travels in the `PoI-Envelope` header to the RS that issued `R0`, `R0` MAY omit `challenge_jws` and carry only `challenge_id` and `node_hash`. RS support for detached mode is OPTIONAL; an RS that does not keep issued challenges MUST reject such an envelope with `malformed_poi_envelope`. Otherwise, and whenever the envelope exceeds 4 KB, it SHOULD be sent in the request body.
* **`R1`:** The decision (`APPROVE`, `REJECT`, or `SUPERCEDE`), referencing `H0` through `target_node_hash` (`APPROVE`/`REJECT`) or `supercedes_node_hash` (`SUPERCEDE`).
* **Node hash for `k >= 1`:** `Hk` is `SHA-256(JCS(node))` over the node object without its `node_hash` member, formatted as in Section 5.3. It therefore covers the decision, the parent hash, the tier claim, and the attestation. `H1` is the CIR `head_node_hash` (Section 7.2).

*Note: Multi-node chains are defined in {{POI-CHAINED}}.*

## Decision Semantics: `APPROVE`, `REJECT`, and `SUPERCEDE`

1. **`APPROVE`:** The signer approves the parameters committed in `H0` unchanged.
2. **`REJECT`:** The signer denies `H0`. The transaction ends.
3. **`SUPERCEDE`:** The signer replaces the parameters of `H0` (`supercedes_node_hash: H0`) with `asserted_params` and `asserted_params_hash`, optionally with a `justification`.
   * Implementations MUST NOT edit `R0` in place. Every change MUST be a `SUPERCEDE` node linked to `H0`.
   * `asserted_params` replaces the proposed parameters completely. Parameters in `R0` that are absent from `asserted_params` MUST NOT reach the executed request.

## Attestation Profiles and Conformance

`R1` carries the evidence of the decision in an attestation container (Section 6.3.1). Any format MUST meet the contract in Section 6.3.2. Formats are registered in Section 11.4.

Tiers are ordered `session-pop` (Tier 1) < `webauthn-uv` (Tier 2) < `webauthn-hw` (Tier 3). A node meets `required_tier` when its attained tier is equal or higher. The attained tier comes from the evidence: the KCT for Tier 1, the RS enrollment record of the credential for Tier 2 and Tier 3. A node's `assurance_tier` is only a claim. The RS MUST reject a node that claims more than its evidence supports, and MUST NOT treat the claim as evidence.

### Abstract Attestation Model and Wire Format

`R1` carries an `assurance_tier` claim and an `attestation` object:

~~~json
{
  "seq": 1,
  "node_type": "APPROVE",
  "target_node_hash": "sha256:9f2c...",
  "assurance_tier": "urn:ietf:params:oauth:poi:tier:webauthn-uv",
  "attestation": {
    "format": "application/psea+jwt",
    "token": "<compact-JWS>"
  }
}
~~~

* `format` (REQUIRED): A registered format identifier (Section 11.4): a media type for JWS profiles, a URN otherwise.
* `token` (REQUIRED): The evidence: a compact JWS string for JWS profiles, or a JSON object for `urn:ietf:params:oauth:poi:attestation:webauthn`.

### Attestation Profile Preconditions (The Conformance Contract)

An RS MUST accept an attestation format only if it meets all six of these:

1. **Parameter commitment:** The attestation commits to `SHA-256(JCS(effective_params))`. For `APPROVE` and `REJECT` this MAY be through the parent hash, since `H0` commits to `raw_params_hash`. For `SUPERCEDE` the attestation itself MUST commit to `asserted_params_hash`. Uncommitted or non-canonical bindings MUST be rejected.
2. **Decision commitment:** The attestation commits to the node's decision. A signature made for one decision MUST NOT verify for another; otherwise an intermediary could relabel a rejection as an approval.
3. **Lineage:** The attestation commits to the parent node hash, so it cannot be moved to another branch or intent.
4. **Intent and challenge binding:** The attestation commits to `intent_id` and `challenge_id`, directly or through the parent hash. A validity window alone is not enough: it would let one attestation answer any challenge with the same parameters while the window is open. A profile with its own validity window MUST carry an expiry, and the verifier MUST enforce it.
5. **Signer and tier:** The attestation identifies the subject (`sub`) and proves the tier: a KCT-certified session key for Tier 1, an enrolled authenticator with user verification for Tier 2 and Tier 3.
6. **Deterministic extraction:** The RS can extract `{decision, parent_node_hash, intent_id, challenge_id, committed_params_hash, sub, attained_tier}` without parsing application payloads. Tier 2 and Tier 3 need the signer's enrollment record (credential ID, public key, subject, credential class). That record is the only RS state needed to verify evidence; admission state is in Section 7.1.

The RS MUST reject an envelope whose attestation fails any of these with `400` (`malformed_poi_envelope`).

### Compliant Attestation Profiles (The Applicability Assessment)

These formats meet Section 6.3.2 when used as specified below.

#### Session Key Proof-of-Possession (`application/poi+jwt;kind=assert`)
* **Primitive:** The EIK (Section 4.1), certified by a KCT (Section 4.2).
* **Tier:** Tier 1 (`urn:ietf:params:oauth:poi:tier:session-pop`).
* **Token:** A compact JWS, `typ: "poi+jwt;kind=assert"`, signed by the EIK, with the KCT in the protected header `kcert`.
* **Payload:** REQUIRED: `aud` (equal to `ico.iss`), `intent_id`, `challenge_id`, `seq` (1 in PoI Core), `decision`, `target_node_hash` (`APPROVE`/`REJECT`) or `supercedes_node_hash` (`SUPERCEDE`), and `client_iat`. For `SUPERCEDE`, also `asserted_params` and `asserted_params_hash`. `justification` is OPTIONAL.
* **Assessment:** Meets all six. The payload signs the decision, parent hash, `intent_id`, and `challenge_id`; parameters are committed through `H0` or `asserted_params_hash`; subject and tier come from the KCT.

#### Post-Session Execution Assurance (`application/psea+jwt`)
* **Primitive:** A device-bound authenticator key (Secure Enclave, StrongBox, TEE) behind biometric or PIN verification ({{PSEA}}).
* **Tiers:** Tier 2. Tier 3 only when the enrollment record shows a roaming hardware authenticator; `psea_tier` is opaque and does not distinguish platform from roaming devices.
* **Header:** Per {{PSEA}} Section 8.2, the JWS `typ` MUST be `"psea-proof+jwt"`; `attestation.format` is `application/psea+jwt`.
* **Required claims:** The RS MUST verify:
  * `aud` equals `ico.iss`;
  * `iss` equals the issuer in the signer's enrollment record;
  * `psea_op` equals `ico.authorization_details.type`;
  * `psea_tier` equals the value agreed for the credential;
  * `psea_payload_hash` equals `SHA-256(JCS(effective_params))`, compared on the decoded digest;
  * `eat_nonce` equals the base64url (unpadded) 32-octet digest of the parent node hash (binds the challenge and lineage);
  * `psea_stepup_selection` equals the base64url (unpadded) `SHA-256(JCS({"decision": <decision>, "target_node_hash": <parent node hash>}))` (binds the decision);
  * `psea_uv.verified` is `true`;
  * `jti` has not been used, per (`iss`, `jti`) (Section 7.1, step 5); and
  * `psea_counter` is greater than the last value accepted for the credential ({{PSEA}} Section 3.10).
* **No `SUPERCEDE`:** A PSEA token cannot carry new parameters. The RS MUST reject a `SUPERCEDE` node attested with `application/psea+jwt`.
* **Lifetime:** `iat` and `exp` are REQUIRED. The RS MUST reject the token at or after `exp`, or before `iat`, beyond a clock skew that SHOULD NOT exceed 60 seconds ({{PSEA}} Section 3.11). Offline audit uses `cir.received_at`.
* **Assessment:** Meets all six as specified. Without `eat_nonce` and `psea_stepup_selection` it commits only to parameters, fails preconditions 2 to 4, and MUST be rejected.

#### Direct WebAuthn Assertion (`urn:ietf:params:oauth:poi:attestation:webauthn`)
* **Primitive:** A {{WebAuthn}} assertion from `navigator.credentials.get()` with `userVerification: "required"`.
* **Tiers:** Tier 2. Tier 3 only when the enrollment record shows a cross-platform hardware authenticator, verified by attestation at registration.
* **Token:** A JSON object: `assertion_payload` (the same claims as the session key payload), and base64url `credential_id`, `authenticator_data`, `client_data_json`, and `signature`.
* **Challenge:** The Signing Vault sets the WebAuthn challenge to the 32-octet `SHA-256(JCS(assertion_payload))`. The RS recomputes it from the payload. The authenticator signature therefore covers the decision, parent hash, `intent_id`, `challenge_id`, and any asserted parameters.
* **Enrollment state:** Per credential, the RS keeps the credential ID, public key, subject, credential class (highest tier), and last signature counter.
* **Assessment:** Meets all six when verified as in Section 7.1.


# Verification, Admission, and Countersigned Intent Receipts (CIR)

Verification (Section 7.1, steps 1 to 4) checks the evidence. It is stateless given trusted keys and, for Tier 2 and Tier 3, enrollment records; offline auditors run the same steps. Admission (step 5) is stateful: the RS consumes the challenge so one approval executes at most once.

## Normative Core Verification and Admission Algorithm

The RS MUST run these steps in order and reject the envelope at the first failure. Verifiers MAY apply a clock skew tolerance to `nbf` and `exp`; it SHOULD NOT exceed 60 seconds.

1. **Root proposal (`R0`):**
   * Verify `chain[0].challenge_jws` (or the cached ICO, if detached): `typ` is `"poi+jwt;kind=chal"` and the signature verifies under the RS key.
   * `ico.iss` equals this RS's issuer. Reject a challenge from another issuer that shares the key (`audience_mismatch`).
   * `chain[0].node_hash` equals `SHA-256(ASCII(challenge_jws))`.
   * `ico.challenge_id` and `ico.exp` are present, and `t_eval <= ico.exp` (and `ico.nbf <= t_eval` when present).
2. **Link (`R1`):**
   * `chain[1].seq == 1`.
   * The parent reference (`target_node_hash` or `supercedes_node_hash`) equals `H0`.
   * For `SUPERCEDE`, `SHA-256(JCS(asserted_params))` over the parsed JSON equals `asserted_params_hash`.
3. **Attestation, decision, and tier (`R1`):**
   * `attestation.format` names a profile in Section 6.3.3, and the token verifies as that profile specifies. Its audience equals `ico.iss` (and, if `kcert.aud` is present, `ico.iss` is in it); it binds `ico.intent_id` and `ico.challenge_id`; its decision equals `node_type`.
   * **`application/poi+jwt;kind=assert` (Tier 1):**
     1. Take `kcert` from the protected header; check `typ` is `"poi+jwt;kind=kct"` and the signature verifies under the Authorization Server key.
     2. With `t_eval` the current time (or `cir.received_at` for audit), check `t_eval <= kcert.exp` (and `kcert.nbf <= t_eval` when present).
     3. Check `typ: "poi+jwt;kind=assert"` and verify the signature under `kcert.cnf.jwk`.
     4. Check the payload has the claims of Section 6.3.3.1 and its `seq`, `decision`, and parent hash match the node.
   * **`application/psea+jwt` (Tier 2 / Tier 3):**
     1. Resolve the enrollment record by `kid` and verify the JWS (`typ: "psea-proof+jwt"`) with the enrolled key. No other key MAY be used when `kid` does not resolve.
     2. Check every requirement of Section 6.3.3.2, including lifetime.
     3. Reject a `SUPERCEDE` node.
   * **`urn:ietf:params:oauth:poi:attestation:webauthn` (Tier 2 / Tier 3):**
     1. Resolve the enrollment record by `credential_id`. No other key MAY be used when it does not resolve.
     2. Compute `base64url(SHA-256(JCS(assertion_payload)))`. In `client_data_json`, check `type == "webauthn.get"`, `challenge` equals that value, and `origin` is the Signing Vault origin. If `crossOrigin` is `true`, check `topOrigin` is an allowed host origin.
     3. Check the RP ID hash in `authenticator_data` equals `SHA-256` of the RP ID, and `UP == 1` and `UV == 1`.
     4. Verify `signature` over `authenticator_data || SHA-256(client_data_json)` with the enrolled key.
     5. If the stored or presented signature counter is non-zero, the presented counter MUST exceed the stored one (checked and advanced in step 5).
   * Derive the attained tier from the evidence (Section 6.3). It MUST meet `ico.required_tier` and the RS policy for the effective parameters; otherwise reject with `insufficient_assurance_tier`.
4. **Effective parameters:**
   * `APPROVE`: `R0.raw_params`.
   * `SUPERCEDE`, if it meets the RS assurance and authority policy: exactly `R1.asserted_params`. Parameters of `R0` absent from `asserted_params` MUST NOT be merged.
   * `REJECT`: record the rejection and stop (`intent_rejected`).
5. **Admission (stateful):**
   * Before executing, the RS MUST atomically record `ico.challenge_id` as consumed. If it is already recorded, the RS MUST reject the envelope with `challenge_replayed`.
   * For `application/psea+jwt`, the RS MUST also atomically consume (`iss`, `jti`) and advance `psea_counter`. For WebAuthn, it MUST advance the signature counter when in use.
   * The consumed record MUST be kept at least until `ico.exp` plus the skew used in step 1; the challenge still verifies until then.
   * The record MUST survive restarts and MUST be shared by every instance that accepts envelopes for the same issuer. A per-process record re-admits the envelope after a restart or on another instance.
   * If the store is unavailable, the RS MUST reject the envelope and SHOULD return `503 Service Unavailable`.
   * Offline auditors run steps 1 to 4 only.

## Countersigned Intent Receipt (CIR)

KCTs are short-lived. Someone who compromises a client later could forge an assertion dated inside an old KCT window and insert it into an audit log. The CIR prevents this:

1. On admitting a PoIE (Section 7.1, step 5) while the KCT is valid, the RS (or a transparency service, {{RFC9943}}) MUST issue a CIR (`typ: "poi+jwt;kind=rcpt"`).
2. The CIR MUST include `received_at`, `intent_id`, `head_node_hash` (`H1`), `committed_params_hash` (`SHA-256(JCS(effective_params))`), and the RS signature.
3. Auditors MUST check `kcert.nbf <= cir.received_at <= kcert.exp` for every Tier 1 assertion in the chain.
4. A CIR records admission: the RS verified and consumed the PoIE at `received_at`. It does not record execution or its outcome. Deployments that need execution evidence SHOULD keep a separate completion record keyed by `intent_id` (Section 9.4). Mapping a CIR to another receipt format, such as {{EP-RECEIPTS}}, requires preserving each format's signed inputs and trust context; matching field names is not sufficient.


# Error Handling and Failure Modes

Authorization Servers, Resource Servers, and verifiers MUST return a specific error code for each failure.

## Error Response Signaling (`PoI-Challenge` and RFC 9457)

1. **`PoI-Challenge` header:** Every `401` or `403` caused by PoI MUST include it:

   ~~~ http
   PoI-Challenge: error="kct_expired",
     error_description="Ephemeral Intent Key expired",
     intent_id="intent_loan_4409"
   ~~~
2. **Problem details ({{RFC9457}}):** The body SHOULD be `application/problem+json` with `poi_error`, `intent_id`, `failed_node_seq`, `required_tier`, and optionally `challenge_jws`.

*Non-normative example of an RFC 9457 Problem Details error response:*

~~~ http
HTTP/1.1 401 Unauthorized
PoI-Challenge: error="kct_expired",
  error_description="KCT expired prior to evaluation time",
  intent_id="intent_loan_4409"
Content-Type: application/problem+json

{
  "type": "urn:ietf:params:oauth:poi:error:kct_expired",
  "title": "Ephemeral Intent Key Certificate Expired",
  "status": 401,
  "detail": "KCT exp (1793391000) < eval time (1793391125).",
  "poi_error": "kct_expired",
  "intent_id": "intent_loan_4409",
  "failed_node_seq": 1
}
~~~

## Cryptographic Signature, Audience, and Key Binding Errors

* **`invalid_kct_signature`** (`401`): The KCT signature fails under the Authorization Server key, names an unknown or revoked `kid`, has the wrong `typ`, or uses `none` or a MAC algorithm.
* **`invalid_ico_signature`** (`400` or client-side): The ICO signature fails or `typ` is wrong. A Signing Vault that detects this MUST NOT show the prompt and MUST NOT sign.
* **`invalid_assertion_signature`** (`401`): The Tier 1 assertion does not verify under `kcert.cnf.jwk`; a PSEA JWS or WebAuthn signature does not verify under the enrolled key; or no enrollment record matches the `kid` or `credential_id`.
* **`audience_mismatch`** (`401`): The attestation audience is not `ico.iss`, `kcert.aud` excludes the RS, or `ico.iss` is not this RS.
* **`invalid_webauthn_attestation`** (`401`): A WebAuthn check failed: `type`, challenge, `origin` or `topOrigin`, RP ID hash, `UP` or `UV`, a non-increasing counter, or a credential class below the claimed tier.
* **`invalid_rollover_proof`** (`401`): The rollover signature does not verify under `K_n` (Section 4.3).

## Temporal and Validity Window Errors (`nbf`, `exp`, `auth_time`, Replay)

* **`kct_not_yet_valid`** (`401`): `t_eval < kcert.nbf` beyond skew.
* **`kct_expired`** (`401`): `t_eval > kcert.exp`, or a rollover signed with an expired `K_n`.
* **`challenge_not_yet_valid`** (`400`): `t_eval < ico.nbf`.
* **`challenge_expired`** (`401` or `403`): `t_eval > ico.exp`. The RS MAY include a new `challenge_jws`.
* **`session_max_age_exceeded`** (`401`): The KCT is valid, but `t_eval - kcert.auth_time` exceeds the RS `max_age` or the Authorization Server session limit.
* **`session_revoked`** (`401`): The KCT `session_id` was terminated before `kcert.exp`.
* **`challenge_replayed`** (`409`): The `challenge_id`, the PSEA (`iss`, `jti`), or a rollover `nonce` was already consumed (Section 7.1, step 5).
* **`intent_outcome_unknown`** (`409`): An earlier admission for the same `intent_id` has no known outcome (Section 9.4). No further approval is admitted until it is resolved.

## Envelope Integrity and Step-Up Errors

* **`malformed_poi_envelope`** (`400`): The envelope cannot be parsed, lacks required claims, or has the wrong `kind`.
* **`chain_continuity_broken`** (`422`): `chain[0].node_hash` is not `SHA-256(ASCII(challenge_jws))`, or the `R1` parent reference is not `H0`.
* **`params_hash_mismatch`** (`422`): A recomputed parameter digest does not match `raw_params_hash`, `asserted_params_hash`, or the WebAuthn challenge.
* **`intent_rejected`** (`422`): `R1` is a valid `REJECT`. The RS records it and stops.
* **`intent_proof_required`** (`403`): No envelope was sent for a protected action. The response carries the ICO (`R0`).
* **`insufficient_assurance_tier`** (`403`): `R1` is valid but below the required tier (for example, a `SUPERCEDE` that raises the required tier).

*Note: Error codes for chains, state drift, and concurrent approvers are defined in {{POI-CHAINED}}.*

## Summary Matrix of PoI Core Error Codes

| `poi_error` Code | Category | HTTP Status | Retryable with New Signature? |
| :--- | :--- | :--- | :--- |
| `intent_proof_required` | Step-Up / Challenge | `403` | Yes (Sign returned ICO) |
| `insufficient_assurance_tier` | Step-Up / Challenge | `403` | Yes (Step up to `required_tier`) |
| `invalid_kct_signature` | Cryptographic | `401` | No (Re-authenticate to IdP) |
| `invalid_ico_signature` | Cryptographic | `400` | No (Abort; potential MITM) |
| `invalid_assertion_signature` | Cryptographic | `401` | No |
| `audience_mismatch` | Cryptographic / Binding | `401` | No (Potential cross-service replay) |
| `invalid_webauthn_attestation` | Cryptographic | `401` | Yes (Retry with valid authenticator) |
| `invalid_rollover_proof` | Cryptographic | `401` | No (Re-authenticate to IdP) |
| `kct_not_yet_valid` | Temporal (`nbf`) | `401` | Yes (After `nbf` or clock sync) |
| `kct_expired` | Temporal (`exp`) | `401` | Yes (Rotate key or re-authenticate) |
| `challenge_not_yet_valid` | Temporal (`nbf`) | `400` | Yes (After `ico.nbf`) |
| `challenge_expired` | Temporal (`exp`) | `401` / `403` | Yes (Sign fresh `challenge_jws`) |
| `session_max_age_exceeded` | Temporal (`auth_time`) | `401` | Yes (After interactive re-auth) |
| `session_revoked` | Temporal / Session | `401` | No (Session terminated) |
| `challenge_replayed` | Replay | `409` | No (Request new challenge) |
| `intent_outcome_unknown` | Recovery | `409` | No (Resolve the prior outcome first) |
| `malformed_poi_envelope` | Syntax / Format | `400` | No |
| `chain_continuity_broken` | Chain Integrity | `422` | No (Tampered or broken link) |
| `params_hash_mismatch` | Payload Integrity | `422` | No (Tampered parameters) |
| `intent_rejected` | Terminal Decision | `422` | No (Human explicitly rejected) |


# Security Considerations

## Confused Deputy and Post-Approval Agent Bypass

After an approval or `SUPERCEDE`, the RS MUST execute the verified parameters itself. It MUST NOT hand them back to an agent to re-submit, which would put the agent back between the signature and the execution. The agent SHOULD receive only the CIR.

PoI Core defines no override, bypass, or standing-approval token. When policy requires proof of intent, only a PoIE that verifies for that request under Section 7.1 is acceptable. The RS MUST NOT accept any other attribute, header, context value, or token instead, and MUST NOT apply a PoIE verified for one request to another. A standing grant for a class of future actions would recreate the reusable capability that per-transaction approval removes; if one is needed, it belongs in a separate specification.

## Key Smuggling, Cross-Origin Vault Isolation, and WebAuthn Permissions Policy

`extractable: false` keeps the EIK from being exfiltrated, but script injection in the host application could still call `crypto.subtle.sign()` as a signing oracle.

Implementations SHOULD keep key generation, key storage, ICO verification, `display_facts` rendering, and the approve button in a small cross-origin iframe (for example, `https://vault.example.org`) with a strict Content Security Policy (`script-src 'self'; object-src 'none'`). The host (`https://app.example.org`) talks to the vault only through `window.postMessage`, passing the signed ICO.

When Tier 2 or Tier 3 {{WebAuthn}} runs inside that iframe, the host MUST delegate access with `Permissions-Policy: publickey-credentials-get=(self "https://vault.example.org")` and the iframe attribute ``allow="publickey-credentials-get"``. Verifiers MUST check `"origin": "https://vault.example.org"` and, when `"crossOrigin": true`, `"topOrigin": "https://app.example.org"`.

## Backdated Forgery After Key Expiry

`client_iat` proves nothing on its own; client clocks can be set. Offline audit MUST rely on `cir.received_at` or an external timestamp or transparency log ({{RFC9943}}) to show the signature existed before `kcert.exp`.

## Application Crash Recovery and Idempotency Demarcation

PoI proves intent. It does not coordinate distributed transactions. It does define what recovery relies on:

1. **Stable occurrence:** `intent_id` names the business occurrence and survives reapproval (Section 5.2); `challenge_id` names one approval.
2. **Retry after admission:** Once a PoIE is admitted (Section 7.1, step 5), retrying the downstream call is application behavior keyed on `intent_id` or the CIR; the application MUST NOT re-present the PoIE (which is rejected with `challenge_replayed`). `intent_id` identifies the occurrence, but does not by itself make a retry safe: unless the provider enforces idempotency on that key, the application has to determine whether the provider already acted before retrying.
3. **Unknown outcomes block reapproval:** If an admitted action has an unknown outcome (the provider may have completed it before a crash or a lost response), the RS MUST NOT admit another PoIE for that `intent_id` until the outcome is resolved as completed or failed, and MUST reject such envelopes with `intent_outcome_unknown`. An admission with no recorded outcome, such as after a crash, counts as unknown.
4. **Idempotency:** The RS SHOULD pass `intent_id` as the idempotency key to providers that support one, and SHOULD record a completion record (Section 7.2) once the outcome is known.

Resolving non-idempotent or partial outcomes is application logic (compensating actions, exception queues). Human signatures MUST NOT be used as an automatic retry mechanism.

## Parameter Replacement Invariants for SUPERCEDE

For a `SUPERCEDE`, the enforcement point MUST replace the executable parameters with `asserted_params` entirely and MUST NOT merge them into `raw_params`. A merge lets parameters the person never reviewed reach execution.

## Consume-Once State and Replay

Consume-once admission (Section 7.1, step 5) is the only control that stops an intermediary from re-presenting a verified envelope while it is still valid. In-process state re-admits the envelope after a restart and on other instances. An entry that expires at `ico.exp` re-admits it during the clock skew interval. The consumed-state store is part of the security boundary: it covers `exp` plus skew, it is shared, and an outage rejects envelopes.

Attestation identifiers such as the PSEA `jti` are consumed in the same store. Challenge binding (Section 6.3.2, precondition 4) already stops one attestation from answering a second challenge; consuming the identifier adds defense in depth.


# Privacy Considerations

1. **Audit minimization:** `display_facts` may contain personal or health data. Implementations MAY store a hash-committed or encrypted form (`display_facts_hash`) in external transparency logs so verifiers can check continuity without the cleartext.
2. **Pseudonymous subjects:** `sub` in KCTs and assertions SHOULD be an opaque identifier (`user:88421`), not an email address or name.


# IANA Considerations

## Media Type Registrations (`application/poi+jwt` and `application/poi-envelope+json`)

This document registers two media types ({{RFC6838}}):

### `application/poi+jwt`
* **Type name:** `application`
* **Subtype name:** `poi+jwt`
* **Required parameters:**
  * `kind`: The PoI artifact. Values:
    * `kct` (Key Certification Token, Section 4.2)
    * `roll` (PoP Key Rollover Request, Section 4.3)
    * `chal` (Intent Challenge Object, Section 5.2)
    * `assert` (Proof-of-Intent Assertion JWS, Section 6.3.3.1)
    * `rcpt` (Countersigned Intent Receipt, Section 7.2)
* **Optional parameters:** None
* **Encoding considerations:** 7-bit ASCII compact JWS ({{RFC7515}}).
* **Security considerations:** See Section 9.

### `application/poi-envelope+json`
* **Type name:** `application`
* **Subtype name:** `poi-envelope+json`
* **Required parameters:** None
* **Optional parameters:** None
* **Encoding considerations:** UTF-8 JSON ({{RFC8259}}).
* **Security considerations:** See Section 9.

## HTTP Header Field Registrations (`PoI-Challenge` and `PoI-Envelope`)

This document registers in the "Hypertext Transfer Protocol (HTTP) Field Name Registry" ({{RFC9110}}):

* **`PoI-Challenge`** (permanent): Challenge and error parameters on `401`/`403` responses (Sections 5.1 and 8.1).
* **`PoI-Envelope`** (permanent): A base64url-encoded `application/poi-envelope+json` on requests (Section 6.1).

## OAuth URI Registrations (Token Type, Assurance Tiers, Error Codes)

This document registers in the "OAuth URI" registry ({{RFC6755}}):

* **Token type URIs ({{RFC8693}}):**
  * `urn:ietf:params:oauth:token-type:poi-kct` (Key Certification Token)
  * `urn:ietf:params:oauth:token-type:poi-roll` (PoP Key Rollover Request)
* **Assurance tier URIs (`urn:ietf:params:oauth:poi:tier`):**
  * `urn:ietf:params:oauth:poi:tier:session-pop` (Tier 1: session key)
  * `urn:ietf:params:oauth:poi:tier:webauthn-uv` (Tier 2: user-verified authenticator)
  * `urn:ietf:params:oauth:poi:tier:webauthn-hw` (Tier 3: cross-platform hardware authenticator)
* **Attestation format URIs (`urn:ietf:params:oauth:poi:attestation`):**
  * `urn:ietf:params:oauth:poi:attestation:webauthn` (Direct WebAuthn assertion, Section 6.3.3.3)
* **PoI error code registry (`urn:ietf:params:oauth:poi:error`):**
  * The 20 error codes in Section 8.5.

## Proof-of-Intent Attestation Formats Registry

This document creates the "Proof-of-Intent Attestation Formats" registry in the "Web Authorization Protocol (oauth)" group.

Registration policy: Specification Required ({{RFC8126}}). A registration gives the format identifier, the specification, the target tiers, and an assessment against the six preconditions of Section 6.3.2.

Initial entries:
* **`application/poi+jwt;kind=assert`**: Session key proof-of-possession (Section 6.3.3.1).
* **`application/psea+jwt`**: {{PSEA}} as profiled in Section 6.3.3.2.
* **`urn:ietf:params:oauth:poi:attestation:webauthn`**: Direct WebAuthn assertion (Section 6.3.3.3).

## JWT Claim Registrations

This document registers in the "JSON Web Token Claims" registry ({{RFC7519}}):

* `prev_jkt`: JWK thumbprint of the previous EIK in a rotation chain.
* `display_facts`: RS-attested human-readable form of the proposed parameters.
* `raw_params_hash`: JCS SHA-256 digest of the proposed parameters.
* `supercedes_node_hash`: Hash of the node replaced by a `SUPERCEDE`.
* `asserted_params_hash`: JCS SHA-256 digest of the human-asserted parameters.


# Implementation Status

Note to RFC Editor: please remove this section and the reference to {{RFC7942}} before publication.

This section records known implementations at the time of posting, per {{RFC7942}}. Listing does not imply IETF endorsement.

* **Organization:** Barefoot Coders, LLC (Mandrel Project).
* **Implementation:** The Mandrel reference implementation, tag `poi-core-01-rc.2` in each repository under `https://gitlab.com/the-mandrel-project/`: `mandrel-go` (verifier library, Go module `v1.1.0-rc.2`), `mandrel-collet` (RS enforcement proxy), `mandrel-spec` (schema and policy contract), `mandrel-cli` (policy validator and generator), and `mandrel-demo` (end-to-end demo). `mandrel-collet` is under the Business Source License 1.1; the others are under the Apache License 2.0.
* **Coverage:** ICO issuance and verification; the session key, PSEA, and WebAuthn profiles of Section 6.3.3 (decision binding, PSEA nonce and selection binding, WebAuthn RP checks, enrollment-derived tiers); the attestation container with canonical node hashes; consume-once admission keyed on `challenge_id`, retained through `exp` plus skew, in a shared durable store, with PSEA `jti` and counter checks; `intent_id` reuse across reapproval; completion records and unknown-outcome tracking (Section 9.4); CIR issuance; Signing Vault refusal of non-conforming `display_facts`.
* **Known gaps:** Parameters are strings only. Detached `R0` is not supported. CIRs are not returned to the caller. `asserted_params` are not yet checked against `editable_schema`. Unknown outcomes are resolved through a library call, without an authenticated operator interface. Legacy node fields (`assertion_jws`, `webauthn_proof`, `assertion_payload`) are still accepted during transition.
* **Maturity:** Prototype; release candidate for review.
* **Testing:** Unit tests include decision relabeling, cross-intent attestation reuse, replay inside the skew interval and after restart, and unknown outcomes; an end-to-end demo covers challenge issuance, approval, `SUPERCEDE`, tampering, and forged user tokens.
* **Contact:** Paul Charles Williams (paul@barefootcoders.com).


# Acknowledgements

The author thanks Mohamad Khalil Yossif for alignment with RATS EAT token architectures and attestation profile modeling, and Iman Schrock for analysis of authorization receipts and application-level crash recovery boundaries and for a source review of the reference implementation.
