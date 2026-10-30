---
title: "Cryptographic Proof-of-Intent (PoI) Core Protocol for Human-in-the-Loop (HITL) Step-Up Authorization"
abbrev: "Proof-of-Intent (PoI) Core"
docname: draft-williams-oauth-poi-core-00
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
  RFC6755:
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
    date: 2026-10
    seriesinfo:
      Internet-Draft: draft-williams-oauth-poi-chained-state-00
  RFC7997:
  RFC9052:
  RFC9421:
  RFC9635:
  I-D.ietf-scitt-architecture:
  I-D.ietf-oauth-transaction-tokens:

--- abstract

Autonomous software agents and orchestrated workflows increasingly invoke high-consequence operations on Resource Servers (such as financial originations or clinical prescriptions) on behalf of human users. Existing bearer tokens and transport-level Proof-of-Possession mechanisms cannot cryptographically distinguish between parameters autonomously synthesized by an intermediary agent and parameters explicitly reviewed, approved, or modified by an authorized human. Furthermore, redirect-based authorization flows impose prohibitive user experience friction for high-frequency Human-in-the-Loop (HITL) interactions.

This document specifies the Proof-of-Intent (PoI) Core Protocol, a stateless, single-hop cryptographic framework building on JSON Web Signature (JWS, RFC 7515), Proof-of-Possession Key Semantics for JWTs (RFC 7800), JSON Web Token Best Current Practices (RFC 8725), JSON Canonicalization Scheme (JCS, RFC 8785), OAuth 2.0 Rich Authorization Requests (RAR, RFC 9396), OAuth 2.0 Step-Up Authentication Challenge Protocol (RFC 9470), and W3C WebAuthn. PoI Core defines: (1) short-lived, client-generated Ephemeral Intent Keys certified at login and rotated via Proof-of-Possession key chaining; (2) Resource Server-signed Intent Challenge Objects binding canonical action parameters to human-readable display facts; (3) multi-tier assurance attestations spanning zero-friction session keys to hardware security tokens; and (4) stateless verification and countersigned audit receipts for single-hop APPROVE, REJECT, and within-authority SUPERCEDE decisions.

Multi-hop chained escalations, asynchronous intent escrowing, and concurrent multi-approver conflict resolution are specified in the companion extension document, draft-williams-oauth-poi-chained-state-00.

--- middle

---

## Table of Contents

1. [Introduction](#1-introduction)
   - 1.1. [Problem Statement](#11-problem-statement)
   - 1.2. [Design Goals and Scope of PoI Core](#12-design-goals-and-scope-of-poi-core)
2. [Conventions and Terminology](#2-conventions-and-terminology)
   - 2.1. [Requirements Language](#21-requirements-language)
   - 2.2. [Terminology](#22-terminology)
   - 2.3. [Parameterized Media Type Conventions (`application/poi+jwt;kind=...`)](#23-parameterized-media-type-conventions-applicationpoijwtkind)
3. [Protocol Architecture and Overview](#3-protocol-architecture-and-overview)
   - 3.1. [Architectural Topology](#31-architectural-topology)
   - 3.2. [Orthogonality to Policy Enforcement](#32-orthogonality-to-policy-enforcement)
4. [Ephemeral Intent Key (EIK) Lifecycle](#4-ephemeral-intent-key-eik-lifecycle)
   - 4.1. [Client-Side Non-Extractable Key Generation and Separation from Transport DPoP](#41-client-side-non-extractable-key-generation-and-separation-from-transport-dpop)
   - 4.2. [Key Certification Token (KCT) via RFC 7800](#42-key-certification-token-kct-via-rfc-7800)
   - 4.3. [Proof-of-Possession (PoP) Key Chaining Rotation and RFC 8693 Binding](#43-proof-of-possession-pop-key-chaining-rotation-and-rfc-8693-binding)
5. [Resource Server Intent Challenge](#5-resource-server-intent-challenge)
   - 5.1. [HTTP 403 Step-Up Challenge Signaling (`PoI-Challenge`)](#51-http-403-step-up-challenge-signaling-poi-challenge)
   - 5.2. [Intent Challenge Object (ICO) Format](#52-intent-challenge-object-ico-format)
   - 5.3. [Canonical Parameter Hashing and Numeric Precision via RFC 8785 (JCS)](#53-canonical-parameter-hashing-and-numeric-precision-via-rfc-8785-jcs)
6. [Proof-of-Intent Envelope (PoIE) Core Profile](#6-proof-of-intent-envelope-poie-core-profile)
   - 6.1. [Two-Node Core Envelope (`[R0, R1]`) and Header Size Considerations](#61-two-node-core-envelope-r0-r1-and-header-size-considerations)
   - 6.2. [Decision Semantics: `APPROVE`, `REJECT`, and `SUPERCEDE`](#62-decision-semantics-approve-reject-and-supercede)
   - 6.3. [Assurance Tiers and Attestation Bindings](#63-assurance-tiers-and-attestation-bindings)
7. [Stateless Verification and Countersigned Intent Receipts (CIR)](#7-stateless-verification-and-countersigned-intent-receipts-cir)
   - 7.1. [Normative Core Verification Algorithm](#71-normative-core-verification-algorithm)
   - 7.2. [Countersigned Intent Receipt (CIR)](#72-countersigned-intent-receipt-cir)
8. [Error Handling and Failure Modes](#8-error-handling-and-failure-modes)
   - 8.1. [Error Response Signaling (`PoI-Challenge` and RFC 9457)](#81-error-response-signaling-poi-challenge-and-rfc-9457)
   - 8.2. [Cryptographic Signature, Audience, and Key Binding Errors](#82-cryptographic-signature-audience-and-key-binding-errors)
   - 8.3. [Temporal and Validity Window Errors (`nbf`, `exp`, `auth_time`, Replay)](#83-temporal-and-validity-window-errors-nbf-exp-auth_time-replay)
   - 8.4. [Envelope Integrity and Step-Up Errors](#84-envelope-integrity-and-step-up-errors)
   - 8.5. [Summary Matrix of PoI Core Error Codes](#85-summary-matrix-of-poi-core-error-codes)
9. [Security Considerations](#9-security-considerations)
   - 9.1. [Confused Deputy and Post-Approval Agent Bypass](#91-confused-deputy-and-post-approval-agent-bypass)
   - 9.2. [Key Smuggling, Cross-Origin Vault Isolation, and WebAuthn Permissions Policy](#92-key-smuggling-cross-origin-vault-isolation-and-webauthn-permissions-policy)
   - 9.3. [Backdated Forgery After Key Expiry](#93-backdated-forgery-after-key-expiry)
10. [Privacy Considerations](#10-privacy-considerations)
11. [IANA Considerations](#11-iana-considerations)
    - 11.1. [Media Type Registrations (`application/poi+jwt` and `application/poi-envelope+json`)](#111-media-type-registrations-applicationpoijwt-and-applicationpoi-envelopejson)
    - 11.2. [HTTP Header Field Registrations (`PoI-Challenge` and `PoI-Envelope`)](#112-http-header-field-registrations-poi-challenge-and-poi-envelope)
    - 11.3. [OAuth URI Registrations (Token Type, Assurance Tiers, Error Codes)](#113-oauth-uri-registrations-token-type-assurance-tiers-error-codes)
    - 11.4. [JWT Claim Registrations](#114-jwt-claim-registrations)
12. [References](#12-references)
    - 12.1. [Normative References](#121-normative-references)
    - 12.2. [Informative References](#122-informative-references)

---

## 1. Introduction

### 1.1. Problem Statement

In architectures employing autonomous AI agents or automated workflow orchestrators, an intermediary software agent acts on behalf of an authenticated human user to invoke tools and APIs hosted by downstream Resource Servers (RS). While OAuth 2.0 ([RFC6749](https://www.rfc-editor.org/rfc/rfc6749)) and Demonstrating Proof-of-Possession (DPoP, [RFC9449](https://www.rfc-editor.org/rfc/rfc9449)) authenticate the client or session, they do not provide cryptographic proof of **human intent** over the specific application-layer parameters of an individual transaction.

This creates three immediate vulnerabilities for synchronous Human-in-the-Loop (HITL) interactions:

1. **The Confused Deputy Problem:** A prompt-injected or malfunctioning agent possessing a valid session token can invoke a privileged Resource Server endpoint with unauthorized parameters.
2. **Semantic UI Misrepresentation (MITM / Spoofing):** If an agent constructs the HITL approval prompt while transmitting raw database identifiers (e.g., UUIDs or drug codes) to the Resource Server, the human may be tricked into signing parameters that do not match the human-readable description displayed on screen.
3. **The OAuth Redirect Tax:** Existing transaction authorization specifications such as Rich Authorization Requests (RAR, [RFC9396](https://www.rfc-editor.org/rfc/rfc9396)) paired with Step-Up Authentication ([RFC9470](https://www.rfc-editor.org/rfc/rfc9470)) require an Authorization Server round-trip or out-of-band push notification per transaction, causing severe cognitive and UX friction during high-frequency HITL operations.

### 1.2. Design Goals and Scope of PoI Core

This document specifies **PoI Core**, the stateless foundation of the Proof-of-Intent protocol family. PoI Core is designed for Resource Servers that want to verify human intent over a proposed transaction (`[R0, R1]`) without maintaining multi-step workflow state tables:

* **Zero Additional Cognitive Overhead at Baseline:** During session login, the client generates a non-extractable asymmetric keypair certified by the Authorization Server with `nbf` and `exp` bounds via [RFC7800](https://www.rfc-editor.org/rfc/rfc7800). Baseline (Tier 1) HITL approvals require only a single user interaction in the client interface with zero Authorization Server round-trips.
* **Extensible Multi-Tier Assurance:** Resource Servers dynamically specify the required assurance tier based on action consequence -- stepping up from Tier 1 (Session PoP Key) to Tier 2 (Platform Biometric via [WebAuthn](https://www.w3.org/TR/webauthn-3/)) or Tier 3 (Cross-Platform Hardware Token via [WebAuthn](https://www.w3.org/TR/webauthn-3/)).
* **Single-Hop Authoritative Edits (`SUPERCEDE`):** If a human operator adjusts parameters proposed by an agent within their own scope of authority, the client submits a two-node envelope (`R0 -> R1`) that immediately supercedes `R0` and asserts the new parameters in `R1`.
* **Companion Chained State Specification:** Multi-party organizational escalations (`R0 -> R1 -> R2`), asynchronous intent escrowing, and concurrent multi-approver race resolution are defined in [POI-CHAINED](./draft-williams-oauth-poi-chained-state-00.md).

---

## 2. Conventions and Terminology

### 2.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

### 2.2. Terminology

* **Ephemeral Intent Key (EIK):** A short-lived asymmetric keypair generated inside the client's Signing Vault with non-extractable private key material, used exclusively to sign Tier 1 HITL assertions.
* **Key Certification Token (KCT):** A JSON Web Token ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519)) signed by the Authorization Server containing an [RFC7800](https://www.rfc-editor.org/rfc/rfc7800) `cnf` claim that binds the user's identity (`sub`), authentication timestamp (`auth_time`), and validity window (`nbf`, `exp`) to the public portion of an EIK.
* **Signing Vault:** A logically isolated client execution context (e.g., a cross-origin isolated iframe or native secure enclave) responsible for holding the EIK private handle, verifying Resource Server challenge signatures, rendering ground-truth display facts, and producing signed assertions.
* **Intent Challenge Object (ICO):** A signed JWS ([RFC7515](https://www.rfc-editor.org/rfc/rfc7515)) issued by a Resource Server when an action requires HITL authorization. The ICO binds the canonical hash of the proposed parameters, the resolved human-readable `display_facts`, and the required assurance tier.
* **Proof-of-Intent Envelope (PoIE):** A JSON structure carrying an ordered, hash-linked array of nodes. In PoI Core, the envelope contains two nodes: the Resource Server's proposal (`R0`) and the human's terminal decision (`R1`: `APPROVE`, `REJECT`, or within-authority `SUPERCEDE`).
* **Countersigned Intent Receipt (CIR):** A signed timestamped receipt produced by the Resource Server (or transparency service) upon verifying a PoIE within its active key window, enabling offline audit verification after the EIK has expired.

### 2.3. Parameterized Media Type Conventions (`application/poi+jwt;kind=...`)

To enforce explicit JWT typing per [RFC8725](https://www.rfc-editor.org/rfc/rfc8725) Section 3.11 without proliferating separate media type registrations, this specification defines a single parameterized JWT media type, `application/poi+jwt` (per [RFC6838](https://www.rfc-editor.org/rfc/rfc6838) Section 4.3), with a required parameter `kind`:

| `kind` Parameter | HTTP `Content-Type` Header | JWS `typ` Header Parameter | Artifact Description |
| :--- | :--- | :--- | :--- |
| `kct` | `application/poi+jwt;kind=kct` | `"poi+jwt;kind=kct"` | Key Certification Token (Section 4.2) |
| `roll` | `application/poi+jwt;kind=roll` | `"poi+jwt;kind=roll"` | PoP Key Rollover Request (Section 4.3) |
| `chal` | `application/poi+jwt;kind=chal` | `"poi+jwt;kind=chal"` | Intent Challenge Object (Section 5.2) |
| `assert` | `application/poi+jwt;kind=assert` | `"poi+jwt;kind=assert"` | Tier 1 Human Assertion JWS (Section 6.3.1) |
| `rcpt` | `application/poi+jwt;kind=rcpt` | `"poi+jwt;kind=rcpt"` | Countersigned Intent Receipt (Section 7.2) |

In accordance with [RFC7515](https://www.rfc-editor.org/rfc/rfc7515) Section 4.1.9, senders SHOULD omit the `"application/"` prefix in the JWS `typ` header parameter (e.g., `"typ": "poi+jwt;kind=chal"`), and verifiers MUST treat `"poi+jwt;kind=<val>"` and `"application/poi+jwt;kind=<val>"` (case-insensitively with optional whitespace after `;`) as equivalent. Verifiers MUST reject any token whose `kind` parameter does not match the expected artifact type for that protocol step.

---

## 3. Protocol Architecture and Overview

### 3.1. Architectural Topology

```text
+--------------------+         (1) Auth + Pub(EIK)        +--------------------+
|                    | ---------------------------------> |                    |
|  Client Signing    | <--------------------------------- |   Authorization    |
|  Vault (Frontend)  |         (2) Signed KCT             |   Server (IdP)     |
|                    |      [nbf, exp, cnf: Pub(EIK)]     |                    |
+--------------------+                                    +--------------------+
   ^              |
   | (5) Verify   | (6) Signed PoIE
   |     ICO &    |     ([R0, R1])
   |     Render   v
+--------------------+         (3) Propose Action         +--------------------+
|                    | ---------------------------------> |                    |
|  AI Orchestrator / | <--------------------------------- |  Resource Server   |
|  Intermediary      |         (4) HTTP 403 + ICO (R0)    |  (Loan / Rx Svc)   |
|                    | ---------------------------------> |                    |
+--------------------+         (7) Submit PoIE ([R0, R1]) +--------------------+
                               (or direct Vault->RS)                |
                                                                    v
                                                          +--------------------+
                                                          | Orthogonal Policy  |
                                                          | Engine & Audit Log |
                                                          +--------------------+
```

### 3.2. Orthogonality to Policy Enforcement

The PoI protocol intentionally separates **cryptographic proof of human intent** from **organizational policy enforcement**:

1. **PoI Verification Layer:** Determines exclusively whether the assertion `R1` over proposal `R0` was produced by the claimed subject, within a valid key window (`[nbf, exp]`), for the target audience (`aud`), at the required assurance tier, over the exact canonical parameter hash.
2. **Orthogonal Policy Layer:** Consumes the verified PoIE output to evaluate organization-specific authorization rules (e.g., dollar thresholds, clinical prescribing authority, role permissions).

---

## 4. Ephemeral Intent Key (EIK) Lifecycle

### 4.1. Client-Side Non-Extractable Key Generation and Separation from Transport DPoP

The Signing Vault MUST generate the EIK asymmetric keypair locally. To guarantee baseline interoperability across implementations:
* Implementations of this specification MUST support `ES256` (ECDSA using P-256 and SHA-256) and SHOULD support `EdDSA` (Ed25519) ([RFC7518](https://www.rfc-editor.org/rfc/rfc7518)).

Normative key isolation rules:
1. The private key MUST NOT be generated by or transmitted to the Authorization Server or any backend service.
2. In browser environments utilizing the Web Cryptography API, the keypair MUST be generated with `extractable: false` and key usages restricted to `["sign"]`.
3. The private key handle SHOULD be retained strictly in volatile memory (RAM) inside a cross-origin isolated Signing Vault context and MUST NOT be serialized to persistent storage.
4. **Separation from Transport DPoP Keys ([RFC9449](https://www.rfc-editor.org/rfc/rfc9449)):** Clients that use DPoP ([RFC9449](https://www.rfc-editor.org/rfc/rfc9449)) for transport-level access token binding MUST NOT reuse their transport DPoP keypair as the Ephemeral Intent Key (EIK). Transport DPoP keys sign automated background HTTP requests (such as polling or telemetry) without human presence, whereas the EIK MUST only be invoked inside the Signing Vault upon an explicit human user gesture.

### 4.2. Key Certification Token (KCT) via RFC 7800

During user authentication, the client submits the EIK public key as a JSON Web Key (JWK, [RFC7517](https://www.rfc-editor.org/rfc/rfc7517)) to the Authorization Server. Upon successful authentication, the Authorization Server issues a Key Certification Token (KCT).

A KCT is a signed JWT ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519)) with the following normative requirements:

* **JWS Protected Header:**
  * `alg`: Asymmetric signature algorithm (`ES256` MTI). `none` and symmetric MAC algorithms (`HS256`) MUST NOT be used.
  * `typ`: MUST be `"poi+jwt;kind=kct"` (or `"application/poi+jwt;kind=kct"`).
  * `kid`: Key identifier of the Authorization Server's signing key.
* **JWT Payload Claims:**
  * `iss` (REQUIRED): Issuer URI of the Authorization Server.
  * `sub` (REQUIRED): Subject identifier of the authenticated human user.
  * `aud` (OPTIONAL): Audience URI(s) identifying the Resource Server trust domain(s) authorized to rely on this KCT.
  * `session_id` (REQUIRED): Unique identifier for the logical authentication session.
  * `auth_time` (REQUIRED): NumericDate (as defined in [RFC7519](https://www.rfc-editor.org/rfc/rfc7519)) when the user last performed interactive primary/multi-factor authentication.
  * `iat` (REQUIRED): NumericDate when this KCT was issued.
  * `nbf` (REQUIRED): NumericDate before which this EIK MUST NOT be accepted for signing.
  * `exp` (REQUIRED): NumericDate after which this EIK MUST NOT be accepted for signing. The lifetime (`exp - nbf`) SHOULD NOT exceed 1800 seconds (30 minutes).
  * `cnf` (REQUIRED): Confirmation claim per [RFC7800](https://www.rfc-editor.org/rfc/rfc7800), containing a `jwk` member representing the client's EIK public key (which MUST NOT contain private key parameters).
  * `prev_jkt` (OPTIONAL): Base64url-encoded JWK Thumbprint ([RFC7638](https://www.rfc-editor.org/rfc/rfc7638)) of the immediately preceding EIK in the same session, present when the KCT was issued via PoP Key Rotation (Section 4.3).

*Non-normative example of a KCT payload:*
```json
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
```

### 4.3. Proof-of-Possession (PoP) Key Chaining Rotation and RFC 8693 Binding

To support sessions longer than a single KCT validity window without relying on smuggle-prone bearer refresh tokens, the Signing Vault rotates keys using **PoP Key Chaining**:

1. Prior to the `exp` time of the active key `K_n`, the Signing Vault generates a fresh non-extractable keypair `K_(n+1)`.
2. The Signing Vault constructs a Key Rollover Request JWS (`typ: "poi+jwt;kind=roll"`) signed using the private key of `K_n`:
   * The JWS Protected Header MUST include `kcert` containing the compact serialization of the currently active KCT for `K_n`.
   * The JWS Payload MUST include `iss` (matching `kcert.sub`), `aud` (matching the Authorization Server's issuer or token endpoint URI), `iat`, a unique `nonce`, and `new_cnf.jwk` containing the public JWK of `K_(n+1)`.
3. **OAuth 2.0 Token Exchange ([RFC8693](https://www.rfc-editor.org/rfc/rfc8693)) Transport Binding:** The client MAY submit the `poi+jwt;kind=roll` JWS to the Authorization Server's standard Token Endpoint using the [RFC8693](https://www.rfc-editor.org/rfc/rfc8693) grant type:
   * `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`
   * `subject_token`: `<Compact-JWS-of-Rollover-Request>`
   * `subject_token_type`: `urn:ietf:params:oauth:token-type:poi-roll`
   * `requested_token_type`: `urn:ietf:params:oauth:token-type:poi-kct`
4. The Authorization Server MUST verify that:
   * The attached `kcert` signature is valid and its `[nbf, exp]` window encompasses the current server time.
   * The `poi+jwt;kind=roll` signature verifies against `kcert.cnf.jwk`, and `aud` matches the Authorization Server.
   * The session identified by `kcert.session_id` has not been revoked and has not exceeded the maximum session lifetime since `kcert.auth_time`.
5. Upon verification, the Authorization Server issues a new KCT for `K_(n+1)` preserving the original `auth_time` and setting `prev_jkt` to the [RFC7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint of `K_n`.
6. Upon receiving the new KCT, the Signing Vault MUST immediately destroy the in-memory handle for `K_n`.

---

## 5. Resource Server Intent Challenge

### 5.1. HTTP 403 Step-Up Challenge Signaling (`PoI-Challenge`)

Because HTTP requests to a Resource Server typically already carry an `Authorization: Bearer` or `Authorization: DPoP` header for transport authentication ([RFC9110](https://www.rfc-editor.org/rfc/rfc9110) Section 11.6.1), PoI avoids overloading the HTTP Authentication Scheme namespace.

When a client or intermediary agent invokes a Resource Server endpoint that requires HITL Proof-of-Intent, the Resource Server MUST respond with an HTTP `403 Forbidden` status code, a **`PoI-Challenge`** response header containing challenge metadata parameters, and a response body of media type `application/poi+jwt;kind=chal`:

```http
HTTP/1.1 403 Forbidden
PoI-Challenge: error="intent_proof_required",
  intent_id="intent_rx_7721",
  required_tier="urn:ietf:params:oauth:poi:tier:session-pop"
Content-Type: application/poi+jwt;kind=chal

<Compact-JWS-of-Intent-Challenge-Object>
```

### 5.2. Intent Challenge Object (ICO) Format

The response body is an Intent Challenge Object (ICO) -- a JWS (`typ: "poi+jwt;kind=chal"`) signed by the Resource Server:

* **JWS Protected Header:**
  * `alg`: Asymmetric signature algorithm of the Resource Server (`ES256` MTI).
  * `typ`: MUST be `"poi+jwt;kind=chal"` (or `"application/poi+jwt;kind=chal"`).
  * `kid`: Key identifier of the Resource Server.
* **ICO Payload Claims:**
  * `iss` (REQUIRED): Resource Server identifier URI.
  * `challenge_id` (REQUIRED): Cryptographically random unique identifier (nonce) for this challenge instance.
  * `intent_id` (REQUIRED): Identifier of the logical transaction.
  * `iat`, `nbf`, `exp` (REQUIRED): Validity window of the challenge. `exp - nbf` SHOULD NOT exceed 300 seconds (5 minutes).
  * `required_tier` (REQUIRED): URN specifying the minimum cryptographic assurance tier required by the Resource Server (Section 6.3).
  * `authorization_details` (REQUIRED): An object conforming to [RFC9396](https://www.rfc-editor.org/rfc/rfc9396) Rich Authorization Requests, extended with the following mandatory PoI members:
    * `type`: Action type URI or string.
    * `actor`: Identifier of the proposing agent or client.
    * `raw_params`: JSON object containing the machine-executable parameters proposed for the transaction.
    * `raw_params_hash`: SHA-256 digest of the canonicalized `raw_params` (Section 5.3).
    * `display_facts`: Ground-truth, human-readable representation resolved by the Resource Server from `raw_params` (e.g., resolving opaque patient/account IDs into human names and descriptions).

### 5.3. Canonical Parameter Hashing and Numeric Precision via RFC 8785 (JCS)

Whenever a parameter object (`raw_params` or `asserted_params`) or assertion payload is hashed in this specification:

1. The JSON object MUST first be serialized into its canonical UTF-8 byte representation using the **JSON Canonicalization Scheme (JCS)** ([RFC8785](https://www.rfc-editor.org/rfc/rfc8785)).
2. A SHA-256 digest ([RFC6234](https://www.rfc-editor.org/rfc/rfc6234)) MUST be computed over the canonical UTF-8 bytes.
3. The digest MUST be formatted as `"sha256:"` followed by the lowercase hexadecimal or base64url encoding of the digest bytes.
4. **Numeric Precision and Deserialization Interoperability:** To prevent IEEE 754 floating-point serialization discrepancies across polyglot runtimes (e.g., `500` vs. `500.0` or decimal rounding), fixed-precision quantities such as currency amounts, interest rates, and clinical dosages in `raw_params` and `asserted_params` SHOULD be represented as JSON strings (e.g., `"60000.00"`, `"6.25"`). Furthermore, verifiers MUST compute `SHA-256(JCS(...))` over the raw parsed JSON tree inside the JWS payload prior to unmarshaling into language-specific domain structs that might strip unknown or null fields.

---

## 6. Proof-of-Intent Envelope (PoIE) Core Profile

### 6.1. Two-Node Core Envelope (`[R0, R1]`) and Header Size Considerations

In PoI Core, a Proof-of-Intent Envelope (`Content-Type: application/poi-envelope+json`) contains a two-element `chain` array (`[R0, R1]`):

* **Node 0 (`R0`, `PROPOSAL`):** Identifies the Resource Server's challenge. Its `node_hash` (`H0`) is `SHA-256(ASCII(challenge_jws))`.
  * **Detached Challenge Optimization (Header Size Control):** Because HTTP reverse proxies commonly enforce a 4 KB to 8 KB per-header limit, when a client submits the PoIE via the `PoI-Envelope` HTTP request header to the same stateful Resource Server that issued `R0`, Node 0 MAY omit the full `challenge_jws` string and include only `challenge_id` and `node_hash: H0` (detached mode). For stateless verification or when the serialized `PoI-Envelope` exceeds 4 KB, the full envelope (including `challenge_jws`) SHOULD be transmitted in the HTTP request body (`Content-Type: application/poi-envelope+json`).
* **Node 1 (`R1`):** Represents the human's decision (`APPROVE`, `REJECT`, or `SUPERCEDE`), referencing `H0` via `target_node_hash` (for `APPROVE`/`REJECT`) or `supercedes_node_hash` (for `SUPERCEDE`).

*Note: Multi-node chains (`seq >= 2`) for organizational escalations are defined in [POI-CHAINED](./draft-williams-oauth-poi-chained-state-00.md).*

### 6.2. Decision Semantics: `APPROVE`, `REJECT`, and `SUPERCEDE`

1. **`APPROVE`**: The human signer attests approval of the exact parameter state committed in `H0` without modification.
2. **`REJECT`**: The human signer explicitly denies `H0`, terminating the transaction.
3. **`SUPERCEDE`**: The human signer rejects the parameters in `H0` (`supercedes_node_hash: H0`) and asserts a replacement parameter object (`asserted_params` and `asserted_params_hash`), optionally accompanied by `justification` metadata.
   * **Normative Rule:** Implementations MUST NOT mutate `R0` in place when a human edits parameters. Every human modification MUST be recorded as a `SUPERCEDE` node linking to `H0`.

### 6.3. Assurance Tiers and Attestation Bindings

Node `R1` MUST be cryptographically signed according to one of the following Assurance Tiers:

#### 6.3.1. Tier 1: Ephemeral Session PoP (`urn:ietf:params:oauth:poi:tier:session-pop`)
* The node contains an `assertion_jws` (`typ: "poi+jwt;kind=assert"`) signed by the client's active EIK.
* The JWS Protected Header MUST contain `"kcert": "<Compact-KCT-JWS>"`.
* Per [RFC8725](https://www.rfc-editor.org/rfc/rfc8725) Section 3.9, the JWS Payload MUST include an **`aud`** claim set to the target Resource Server's `iss` URI from the `ICO`, alongside `intent_id`, `challenge_id`, `seq: 1`, `decision`, `supercedes_node_hash` (or `target_node_hash`), and `client_iat`.
* Requires zero out-of-band prompts beyond clicking the action button inside the Signing Vault.

#### 6.3.2. Tier 2: Platform Biometric / User Verification (`urn:ietf:params:oauth:poi:tier:webauthn-uv`)
* The Signing Vault invokes W3C [WebAuthn](https://www.w3.org/TR/webauthn-3/) `navigator.credentials.get()` with `userVerification: "required"`.
* The WebAuthn `challenge` parameter MUST be set to the raw 32-byte `SHA-256(JCS(assertion_payload))` digest (where `assertion_payload` includes `aud` matching `ico.iss`).
* In the returned `authenticatorData`, both Bit 0 (`UP` - User Present) and Bit 2 (`UV` - User Verified) MUST be set (`1`).
* Optionally, the Signing Vault MAY also sign the bundle with the Tier 1 EIK to bind the hardware assertion to the active `session_id`.

#### 6.3.3. Tier 3: Cross-Platform Hardware Token (`urn:ietf:params:oauth:poi:tier:webauthn-hw`)
* Identical to Tier 2, except the WebAuthn ceremony MUST be restricted to `allowCredentials` corresponding to registered cross-platform/roaming hardware authenticators (e.g., FIDO2 hardware security keys) verified via authenticator attestation during registration.

---

## 7. Stateless Verification and Countersigned Intent Receipts (CIR)

### 7.1. Normative Core Verification Algorithm

A Resource Server or offline verifier validating a PoI Core envelope (`[R0, R1]`) MUST execute the following steps in order. Verifiers MAY apply a configurable clock skew tolerance when evaluating `nbf` and `exp` claims, which SHOULD NOT exceed 60 seconds. If any step fails, verification MUST fail immediately:

1. **Validate Root Proposal (`R0`):**
   * Parse `chain[0].challenge_jws` (or retrieve the cached ICO via `challenge_id` if detached), verify `typ` is `"poi+jwt;kind=chal"`, and verify its signature using the Resource Server's trusted public key.
   * Confirm `chain[0].node_hash == SHA-256(ASCII(challenge_jws))`.
   * At ingestion time, confirm current server time `t_eval` satisfies `ico.nbf <= t_eval <= ico.exp` and `ico.challenge_id` has not been previously consumed.
2. **Validate Link and Digests (`R1`):**
   * Confirm `chain[1].seq == 1`.
   * Confirm the parent reference (`target_node_hash` for `APPROVE`/`REJECT`, or `supercedes_node_hash` for `SUPERCEDE`) equals `chain[0].node_hash` (`H0`).
   * Confirm `assertion.aud == ico.iss` (and, if `kcert.aud` is present, confirm `ico.iss` is in `kcert.aud`).
   * If `chain[1].node_type == "SUPERCEDE"`, recompute `SHA-256(JCS(asserted_params))` over the raw JSON tree and confirm it matches `asserted_params_hash`.
3. **Validate Signer Credentials and Assurance Tier (`R1`):**
   * **For Tier 1 (`session-pop`):**
     1. Extract `kcert` from the protected header, verify its `typ` is `"poi+jwt;kind=kct"`, and verify its signature against the Authorization Server's trusted public key.
     2. Let `t_eval` be the current server time (at ingestion) or `cir.received_at` (during offline audit). Confirm `kcert.nbf <= t_eval <= kcert.exp`.
     3. Verify `assertion_jws` has `typ: "poi+jwt;kind=assert"` and verify its signature using the public key in `kcert.cnf.jwk`.
   * **For Tier 2 / Tier 3 (`webauthn-uv` / `webauthn-hw`):**
     1. Parse `clientDataJSON` and confirm `type == "webauthn.get"`, `challenge == base64url(SHA-256(JCS(assertion_payload)))`, and `origin` matches the configured Signing Vault origin. If `clientDataJSON.crossOrigin == true` (when the Signing Vault is an embedded cross-origin iframe), confirm `clientDataJSON.topOrigin` matches the allowlisted host application origin.
     2. Verify the RP ID hash in `authenticatorData` and confirm `UP == 1` and `UV == 1`.
     3. Verify the WebAuthn signature against the registered credential public key associated with the signer and confirm the credential class matches the tier (`platform` vs. `cross-platform` hardware).
4. **Determine Effective Parameter State:**
   * If `R1` is `APPROVE`, the effective parameters are `R0.raw_params`.
   * If `R1` is `SUPERCEDE` and satisfies the Resource Server's assurance and authority policy, the effective parameters are `R1.asserted_params`.

### 7.2. Countersigned Intent Receipt (CIR)

Because EIK certificates (`KCT`) are short-lived, an attacker who compromises a client host *after* a KCT expires (or just before expiry) might attempt to forge a backdated assertion timestamped inside `[nbf, exp]` and inject it into an audit database later.

To defeat backdated audit forgery:
1. Immediately upon verifying a PoIE while the KCT is within its active `[nbf, exp]` window, the Resource Server (or an append-only transparency service per [SCITT](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)) MUST generate a **Countersigned Intent Receipt (CIR)** (`typ: "poi+jwt;kind=rcpt"`).
2. The CIR MUST include `received_at` (server ingestion NumericDate), `intent_id`, `head_node_hash` (`H1`), `committed_params_hash`, and the Resource Server's cryptographic signature.
3. Offline auditors MUST verify that `kcert.nbf <= cir.received_at <= kcert.exp` for all Tier 1 assertions in the receipted chain.

---

## 8. Error Handling and Failure Modes

When an Authorization Server, Resource Server, or Verifier rejects a PoI request, rollover request, or Proof-of-Intent Envelope (PoIE), it MUST return a deterministic error code corresponding to the specific failure mode.

### 8.1. Error Response Signaling (`PoI-Challenge` and RFC 9457)

Resource Servers and Authorization Servers signal PoI errors using two complementary mechanisms:

1. **`PoI-Challenge` Response Header:** For HTTP `401 Unauthorized` and `403 Forbidden` responses triggered by a PoI failure, the server MUST include a `PoI-Challenge` header:
   ```http
   PoI-Challenge: error="kct_expired",
     error_description="Ephemeral Intent Key certificate expired at 1793391000",
     intent_id="intent_loan_4409"
   ```
2. **Problem Details JSON Body ([RFC9457](https://www.rfc-editor.org/rfc/rfc9457)):** The server SHOULD return an HTTP response body formatted as `application/problem+json` per [RFC9457](https://www.rfc-editor.org/rfc/rfc9457), extended with `poi_error`, `intent_id`, `failed_node_seq`, `required_tier`, and an optional `challenge_jws`.

*Non-normative example of an RFC 9457 Problem Details error response:*
```http
HTTP/1.1 401 Unauthorized
PoI-Challenge: error="kct_expired",
  error_description="KCT exp (1793391000) is prior to evaluation time (1793391125)"
Content-Type: application/problem+json

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

### 8.2. Cryptographic Signature, Audience, and Key Binding Errors

* **`invalid_kct_signature`** (HTTP `401 Unauthorized`):
  * *Trigger:* The Key Certification Token (`kcert`) signature in a Tier 1 assertion or key rollover request fails verification against the Authorization Server's trusted public key, references an unknown/revoked `kid`, has an invalid `typ` (`!= "poi+jwt;kind=kct"`), or specifies a disallowed `alg` (`none` or symmetric MAC).
* **`invalid_ico_signature`** (HTTP `400 Bad Request` or Client-Side Rejection):
  * *Trigger:* The root Intent Challenge Object (`chain[0].challenge_jws`) fails signature verification against the Resource Server's public key or has `typ != "poi+jwt;kind=chal"`. If the Signing Vault detects this error upon receiving a challenge from an intermediary agent, the Signing Vault MUST refuse to render the approval prompt and MUST abort signing immediately.
* **`invalid_assertion_signature`** (HTTP `401 Unauthorized`):
  * *Trigger:* For Tier 1, the JWS signature on `assertion_jws` does not verify using `kcert.cnf.jwk`. For Tier 2/3, the WebAuthn `signature` does not verify over `authenticatorData || SHA-256(clientDataJSON)` using the user's registered credential public key.
* **`audience_mismatch`** (HTTP `401 Unauthorized`):
  * *Trigger:* The `aud` claim in `assertion_jws` (or `assertion_payload`) does not match the Resource Server's `iss` URI in the ICO (`assertion.aud != ico.iss`), or `kcert.aud` is present and excludes the Resource Server.
* **`invalid_webauthn_attestation`** (HTTP `401 Unauthorized`):
  * *Trigger:* In a Tier 2 or Tier 3 assertion, one or more WebAuthn verification invariants failed (`clientDataJSON.type != "webauthn.get"`, `origin` or `topOrigin` mismatch, RP ID hash mismatch, `UP` or `UV` bit is `0`, or authenticator class does not match the tier requirement).
* **`invalid_rollover_proof`** (HTTP `401 Unauthorized`):
  * *Trigger:* During PoP Key Chaining Rotation (Section 4.3), the signature on the `poi+jwt;kind=roll` request fails verification under the active predecessor key `K_n` specified in `kcert.cnf.jwk`.

### 8.3. Temporal and Validity Window Errors (`nbf`, `exp`, `auth_time`, Replay)

* **`kct_not_yet_valid`** (HTTP `401 Unauthorized`):
  * *Trigger:* Evaluation timestamp `t_eval < kcert.nbf` (beyond clock skew tolerance, which SHOULD NOT exceed 60 seconds).
* **`kct_expired`** (HTTP `401 Unauthorized`):
  * *Trigger:* Evaluation timestamp `t_eval > kcert.exp`, or a client attempts to sign a PoP key rollover request using an expired predecessor key `K_n`.
* **`challenge_not_yet_valid`** (HTTP `400 Bad Request`):
  * *Trigger:* Evaluation timestamp `t_eval < ico.nbf`.
* **`challenge_expired`** (HTTP `401 Unauthorized` or `403 Forbidden`):
  * *Trigger:* Evaluation timestamp `t_eval > ico.exp`. The Resource Server MAY include a newly minted `challenge_jws` in the error response.
* **`session_max_age_exceeded`** (HTTP `401 Unauthorized`):
  * *Trigger:* Although the current KCT is within `[nbf, exp]`, `(t_eval - kcert.auth_time)` exceeds either the Resource Server's required freshness policy (`max_age`) or the Authorization Server's maximum session lifetime.
* **`session_revoked`** (HTTP `401 Unauthorized`):
  * *Trigger:* The logical `session_id` referenced in the KCT has been administratively terminated or logged out prior to `kcert.exp`.
* **`challenge_replayed`** (HTTP `409 Conflict`):
  * *Trigger:* The `challenge_id` in the ICO or the `nonce` in a key rollover request has already been consumed.

### 8.4. Envelope Integrity and Step-Up Errors

* **`malformed_poi_envelope`** (HTTP `400 Bad Request`):
  * *Trigger:* The `PoI-Envelope` header or body cannot be parsed as valid JSON/JWS, omits required claims, or has a mismatched `typ` parameter (`kind`).
* **`chain_continuity_broken`** (HTTP `422 Unprocessable Content`):
  * *Trigger:* `chain[0].node_hash` does not match `SHA-256(ASCII(challenge_jws))`, or `R1`'s parent hash pointer (`target_node_hash` or `supercedes_node_hash`) does not equal `H0`.
* **`params_hash_mismatch`** (HTTP `422 Unprocessable Content`):
  * *Trigger:* Recomputed `SHA-256(JCS(params))` does not match the signed `raw_params_hash` or `asserted_params_hash` (or WebAuthn `clientDataJSON.challenge`), indicating parameter tampering.
* **`intent_rejected`** (HTTP `422 Unprocessable Content`):
  * *Trigger:* `R1` is a valid `REJECT` assertion node; the Resource Server records the rejection and aborts execution permanently.
* **`intent_proof_required`** (HTTP `403 Forbidden`):
  * *Trigger:* No `PoI-Envelope` was provided for a protected action; response includes the initial `challenge_jws` (`R0`).
* **`insufficient_assurance_tier`** (HTTP `403 Forbidden`):
  * *Trigger:* `R1` is cryptographically valid, but its assurance tier is lower than required by the Resource Server (e.g., when a `SUPERCEDE` parameter edit crosses into a higher assurance requirement).

*(Note: Additional error codes for multi-hop escalations, asynchronous TOCTOU state drift, and concurrent approver Compare-and-Swap conflicts are defined in [POI-CHAINED](./draft-williams-oauth-poi-chained-state-00.md).)*

### 8.5. Summary Matrix of PoI Core Error Codes

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
| `malformed_poi_envelope` | Syntax / Format | `400` | No |
| `chain_continuity_broken` | Chain Integrity | `422` | No (Tampered or broken link) |
| `params_hash_mismatch` | Payload Integrity | `422` | No (Tampered parameters) |
| `intent_rejected` | Terminal Decision | `422` | No (Human explicitly rejected) |

---

## 9. Security Considerations

### 9.1. Confused Deputy and Post-Approval Agent Bypass

When a human approves an action or asserts modified parameters via `SUPERCEDE`, the Resource Server MUST execute the verified canonical parameters directly. The Resource Server MUST NOT return modified parameters to an autonomous LLM or AI agent for re-interpretation or re-submission, as doing so re-introduces the agent as a potential confused deputy between human signature and state execution. The intermediary agent SHOULD receive only a read-only execution receipt (`CIR`).

### 9.2. Key Smuggling, Cross-Origin Vault Isolation, and WebAuthn Permissions Policy

Generating the EIK with `extractable: false` prevents exfiltration of raw private key bytes over the network. However, an attacker achieving Cross-Site Scripting (XSS) within a complex web application could attempt to invoke `crypto.subtle.sign()` in-situ (acting as a signing oracle).

To mitigate signing oracle abuse for Tier 1 keys, implementations SHOULD isolate key generation, key storage, ICO signature verification, `display_facts` rendering, and the physical approval button inside a dedicated, minimal cross-origin iframe (e.g., `https://vault.example.org`) enforced with a strict Content Security Policy (`script-src 'self'; object-src 'none'`). The host application (`https://app.example.org`) communicates with the Signing Vault exclusively via `window.postMessage` by passing the Resource Server's signed ICO.

**WebAuthn Cross-Origin Iframe Delegation:** When Tier 2 or Tier 3 [WebAuthn](https://www.w3.org/TR/webauthn-3/) ceremonies are invoked from within a cross-origin Signing Vault iframe (`https://vault.example.org`), the embedding host document (`https://app.example.org`) MUST delegate credential access via the HTTP `Permissions-Policy` header (`Permissions-Policy: publickey-credentials-get=(self "https://vault.example.org")`) and the iframe `allow` attribute (`<iframe src="https://vault.example.org/..." allow="publickey-credentials-get">`). Verifiers validating the resulting `clientDataJSON` MUST verify both `"origin": "https://vault.example.org"` and, when `"crossOrigin": true`, `"topOrigin": "https://app.example.org"`.

### 9.3. Backdated Forgery After Key Expiry

Verification of `client_iat` alone is insufficient for offline non-repudiation because client clocks can be falsified. Offline audit verification MUST rely on the Resource Server's Countersigned Intent Receipt (`cir.received_at`) or an external timestamp authority / transparency log ([SCITT](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)) to prove the signature existed prior to `kcert.exp`.

---

## 10. Privacy Considerations

1. **Data Minimization in Audit Logs:** `display_facts` inside an ICO may contain Sensitive Personal Information (SPI) or Protected Health Information (PHI). When storing PoIEs in external transparency logs, implementations MAY place human-readable PII in an encrypted or hash-committed detachment (`display_facts_hash`) so that external verifiers can validate hash continuity without inspecting cleartext PHI.
2. **Pseudonymous Subject Identifiers:** The `sub` claim in KCTs and assertions SHOULD use opaque organizational identifiers (e.g., `user:88421`) rather than cleartext email addresses or names.

---

## 11. IANA Considerations

### 11.1. Media Type Registrations (`application/poi+jwt` and `application/poi-envelope+json`)

This document requests registration of two media types in the IANA "Media Types" registry ([RFC6838](https://www.rfc-editor.org/rfc/rfc6838)):

#### 11.1.1. `application/poi+jwt`
* **Type name:** `application`
* **Subtype name:** `poi+jwt`
* **Required parameters:**
  * `kind`: Identifies the specific PoI JWT artifact class. Permitted values are:
    * `kct` (Key Certification Token, Section 4.2)
    * `roll` (PoP Key Rollover Request, Section 4.3)
    * `chal` (Intent Challenge Object, Section 5.2)
    * `assert` (Proof-of-Intent Assertion JWS, Section 6.3.1)
    * `rcpt` (Countersigned Intent Receipt, Section 7.2)
* **Optional parameters:** None
* **Encoding considerations:** 7-bit ASCII compact JWS serialization per [RFC7515](https://www.rfc-editor.org/rfc/rfc7515).
* **Security considerations:** See Section 9 of this document.

#### 11.1.2. `application/poi-envelope+json`
* **Type name:** `application`
* **Subtype name:** `poi-envelope+json`
* **Required parameters:** None
* **Optional parameters:** None
* **Encoding considerations:** UTF-8 JSON per [RFC8259](https://www.rfc-editor.org/rfc/rfc8259).
* **Security considerations:** See Section 9 of this document.

### 11.2. HTTP Header Field Registrations (`PoI-Challenge` and `PoI-Envelope`)

This document registers the following HTTP header fields in the "Hypertext Transfer Protocol (HTTP) Field Name Registry" ([RFC9110](https://www.rfc-editor.org/rfc/rfc9110)):

* **`PoI-Challenge`** (Status: permanent): Carries challenge and error parameters from a Resource Server or Authorization Server on HTTP `401`/`403` responses (Sections 5.1 and 8.1).
* **`PoI-Envelope`** (Status: permanent): Carries a base64url-encoded `application/poi-envelope+json` structure on HTTP requests (Section 6.1).

### 11.3. OAuth URI Registrations (Token Type, Assurance Tiers, Error Codes)

This document registers the following URNs in the "OAuth URI" registry ([RFC6755](https://www.rfc-editor.org/rfc/rfc6755)):

* **Token Type URIs ([RFC8693](https://www.rfc-editor.org/rfc/rfc8693)):**
  * `urn:ietf:params:oauth:token-type:poi-kct` (Key Certification Token)
  * `urn:ietf:params:oauth:token-type:poi-roll` (PoP Key Rollover Request)
* **Assurance Tier URIs (`urn:ietf:params:oauth:poi:tier`):**
  * `urn:ietf:params:oauth:poi:tier:session-pop` (Tier 1: Ephemeral Session Key)
  * `urn:ietf:params:oauth:poi:tier:webauthn-uv` (Tier 2: Platform Biometric / User Verification)
  * `urn:ietf:params:oauth:poi:tier:webauthn-hw` (Tier 3: Cross-Platform Hardware Authenticator)
* **PoI Error Code Registry (`urn:ietf:params:oauth:poi:error`):**
  * Populated with the 19 core error codes defined in Section 8.5.

### 11.4. JWT Claim Registrations

This document registers the following claims in the IANA "JSON Web Token Claims" registry ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519)):

* `prev_jkt`: JWK Thumbprint of the predecessor ephemeral key in a PoP rotation chain.
* `display_facts`: Resource Server-attested human-readable representation of proposed transaction parameters.
* `raw_params_hash`: Canonical SHA-256 digest (via RFC 8785 JCS) of proposed parameters.
* `supercedes_node_hash`: Hash of the prior assertion node superceded by a `SUPERCEDE` transition.
* `asserted_params_hash`: Canonical SHA-256 digest (via RFC 8785 JCS) of human-modified parameters.

---

## 12. References

### 12.1. Normative References

* **[RFC2119](https://www.rfc-editor.org/rfc/rfc2119)** -- Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.
* **[RFC6234](https://www.rfc-editor.org/rfc/rfc6234)** -- Eastlake 3rd, D. and T. Hansen, "US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)", RFC 6234, DOI 10.17487/RFC6234, May 2011.
* **[RFC6749](https://www.rfc-editor.org/rfc/rfc6749)** -- Hardt, D., Ed., "The OAuth 2.0 Authorization Framework", RFC 6749, DOI 10.17487/RFC6749, October 2012.
* **[RFC6755](https://www.rfc-editor.org/rfc/rfc6755)** -- Campbell, B. and H. Tschofenig, "An IETF URN Sub-Namespace for OAuth", RFC 6755, DOI 10.17487/RFC6755, October 2012.
* **[RFC6838](https://www.rfc-editor.org/rfc/rfc6838)** -- Freed, N., Klensin, J., and T. Hansen, "Media Type Specifications and Registration Procedures", BCP 13, RFC 6838, DOI 10.17487/RFC6838, January 2013.
* **[RFC7515](https://www.rfc-editor.org/rfc/rfc7515)** -- Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515, DOI 10.17487/RFC7515, May 2015.
* **[RFC7517](https://www.rfc-editor.org/rfc/rfc7517)** -- Jones, M., "JSON Web Key (JWK)", RFC 7517, DOI 10.17487/RFC7517, May 2015.
* **[RFC7518](https://www.rfc-editor.org/rfc/rfc7518)** -- Jones, M., "JSON Web Algorithms (JWA)", RFC 7518, DOI 10.17487/RFC7518, May 2015.
* **[RFC7519](https://www.rfc-editor.org/rfc/rfc7519)** -- Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, DOI 10.17487/RFC7519, May 2015.
* **[RFC7638](https://www.rfc-editor.org/rfc/rfc7638)** -- Jones, M. and N. Sakimura, "JSON Web Key (JWK) Thumbprint", RFC 7638, DOI 10.17487/RFC7638, September 2015.
* **[RFC7800](https://www.rfc-editor.org/rfc/rfc7800)** -- Jones, M., Bradley, J., and H. Tschofenig, "Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)", RFC 7800, DOI 10.17487/RFC7800, April 2016.
* **[RFC8174](https://www.rfc-editor.org/rfc/rfc8174)** -- Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017.
* **[RFC8259](https://www.rfc-editor.org/rfc/rfc8259)** -- Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, DOI 10.17487/RFC8259, December 2017.
* **[RFC8693](https://www.rfc-editor.org/rfc/rfc8693)** -- Jones, M., Nadalin, A., Campbell, B., Ed., Bradley, J., and C. Mortimore, "OAuth 2.0 Token Exchange", RFC 8693, DOI 10.17487/RFC8693, January 2020.
* **[RFC8725](https://www.rfc-editor.org/rfc/rfc8725)** -- Sheffer, Y., Hardt, D., and M. Jones, "JSON Web Token Best Current Practices", BCP 225, RFC 8725, DOI 10.17487/RFC8725, February 2020.
* **[RFC8785](https://www.rfc-editor.org/rfc/rfc8785)** -- Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, DOI 10.17487/RFC8785, June 2020.
* **[RFC9110](https://www.rfc-editor.org/rfc/rfc9110)** -- Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP Semantics", STD 97, RFC 9110, DOI 10.17487/RFC9110, June 2022.
* **[RFC9396](https://www.rfc-editor.org/rfc/rfc9396)** -- Lodderstedt, T., Richer, J., and B. Campbell, "OAuth 2.0 Rich Authorization Requests", RFC 9396, DOI 10.17487/RFC9396, May 2023.
* **[RFC9449](https://www.rfc-editor.org/rfc/rfc9449)** -- Fett, D., Campbell, B., Bradley, J., Lodderstedt, T., Jones, M., and D. Waite, "OAuth 2.0 Demonstrating Proof of Possession (DPoP)", RFC 9449, DOI 10.17487/RFC9449, September 2023.
* **[RFC9457](https://www.rfc-editor.org/rfc/rfc9457)** -- Nottingham, M., Wilde, E., and S. Dalal, "Problem Details for HTTP APIs", RFC 9457, DOI 10.17487/RFC9457, July 2023.
* **[RFC9470](https://www.rfc-editor.org/rfc/rfc9470)** -- Bertocci, V. and B. Campbell, "OAuth 2.0 Step Up Authentication Challenge Protocol", RFC 9470, DOI 10.17487/RFC9470, September 2023.
* **[WebAuthn](https://www.w3.org/TR/webauthn-3/)** -- Hodges, J., Jones, M., Lindemann, R., and E. Lundberg, "Web Authentication: An API for accessing Public Key Credentials Level 3", W3C Candidate Recommendation, 2024.

### 12.2. Informative References

* **[POI-CHAINED](./draft-williams-oauth-poi-chained-state-00.md)** -- Williams, P. C., "Proof-of-Intent (PoI) Chained State, Multi-Party Escalation, and Concurrency Extension", Work in Progress, Internet-Draft, `draft-williams-oauth-poi-chained-state-00`, October 2026.
* **[RFC7997](https://www.rfc-editor.org/rfc/rfc7997)** -- Flanagan, H., Ed., "The Use of Non-ASCII Characters in RFCs", RFC 7997, DOI 10.17487/RFC7997, December 2016.
* **[RFC9052](https://www.rfc-editor.org/rfc/rfc9052)** -- Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures and Process", STD 96, RFC 9052, DOI 10.17487/RFC9052, August 2022.
* **[RFC9421](https://www.rfc-editor.org/rfc/rfc9421)** -- Backman, A., Ed., Richer, J., Ed., and M. Sporny, "HTTP Message Signatures", RFC 9421, DOI 10.17487/RFC9421, February 2024.
* **[RFC9635](https://www.rfc-editor.org/rfc/rfc9635)** -- Richer, J., Ed. and F. Imbault, "Grant Negotiation and Authorization Protocol (GNAP)", RFC 9635, DOI 10.17487/RFC9635, October 2024.
* **[SCITT](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)** -- Birkholz, H., Delignat-Lavaud, A., Fournet, C., Deshpande, Y., and S. Lasker, "An Architecture for Trustworthy and Transparent Digital Supply Chains", Work in Progress, Internet-Draft, `draft-ietf-scitt-architecture`.
* **[TraTs](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)** -- Tulshibagwale, A., Fletcher, G., and P. Kasselman, "Transaction Tokens for OAuth 2.0", Work in Progress, Internet-Draft, `draft-ietf-oauth-transaction-tokens`.

---

## Author's Address

```text
Paul Charles Williams
Barefoot Coders, LLC
Mandrel Project (https://mandrelproject.ai)
Email: paul@barefootcoders.com
URI:   https://mandrelproject.ai
```
