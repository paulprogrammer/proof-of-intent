# Standards Alignment & RFC Mapping

While no single existing standard defines the complete end-to-end **Proof-of-Intent (PoI)** workflow for AI agent HITL interactions, nearly every primitive in this framework maps directly onto established IETF RFCs, W3C specifications, and OpenID standards.

By composing wire formats from these open standards, implementations can use off-the-shelf JOSE/JWT and WebAuthn libraries across any language stack without inventing proprietary cryptography formats.

---

## 1. Standards Mapping Matrix

| PoI Framework Component | Corresponding Open Standard / RFC | Role in the Architecture |
| :--- | :--- | :--- |
| **IdP-Signed Ephemeral Key Certificate (`[nbf, exp]`)** | **[RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800)** -- *Proof-of-Possession Key Semantics for JWTs* | Defines the `cnf` (Confirmation) claim (`"cnf": { "jwk": ... }`) used by the IdP to bind a user's session identity and `[nbf, exp]` validity window to a client-generated public key. |
| **Client-Generated Non-Extractable Key Signing** | **[RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)** -- *OAuth 2.0 Demonstrating Proof of Possession (DPoP)* | Standardizes generating non-extractable asymmetric keys in the browser (`SubtleCrypto`) and signing short-lived JWS proofs. PoI extends this pattern from transport binding to application-level payload signing. |
| **HTTP Request & Body Digest Signing** | **[RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421)** -- *HTTP Message Signatures* & **[RFC 9530](https://datatracker.ietf.org/doc/html/rfc9530)** -- *Digest Fields* | Provides standard HTTP header conventions when passing signed intent proofs at the gateway/transport boundary. |
| **Downstream Service Demanding Step-Up Assurance** | **[RFC 9470](https://datatracker.ietf.org/doc/html/rfc9470)** -- *OAuth 2.0 Step Up Authentication Challenge Protocol* | Defines how a Resource Server rejects an under-authenticated request (`401`/`403`) and returns required assurance levels (`acr_values`) and freshness (`max_age`). |
| **Structured Action Payloads (WYSIWYS)** | **[RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396)** -- *OAuth 2.0 Rich Authorization Requests (RAR)* | Defines structured JSON `authorization_details` for expressing fine-grained transaction parameters (e.g., loan terms, prescription orders) rather than coarse OAuth scopes. |
| **Key Thumbprints for PoP Chaining** | **[RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)** -- *JSON Web Key (JWK) Thumbprint* | Computes canonical `prev_jkt` hashes to cryptographically link rotated ephemeral keys (`K_1 -> K_2 -> K_3`). |
| **Async / Decoupled HITL Prompting** | **OpenID Connect CIBA** & **[RFC 9635](https://datatracker.ietf.org/doc/html/rfc9635)** -- *GNAP* | Covers decoupled flows where an autonomous agent initiates a request and a human approves it asynchronously via a signed request object. |
| **Tier 2/3 Biometric & Hardware Token Proofs** | **W3C WebAuthn Level 3** & **W3C Secure Payment Confirmation (SPC)** | Standardizes signing arbitrary `challenge` hashes inside hardware enclaves/YubiKeys with cryptographic flags for User Presence (`UP`) and User Verification (`UV`). |
| **Microservice Call Context Integrity** | **IETF `draft-ietf-oauth-transaction-tokens` (TraTs)** | Active IETF OAuth Working Group draft binding immutable transaction context across internal service calls to prevent confused-deputy mutations. |
| **Countersigned Tamper-Evident Receipts** | **IETF SCITT** (*Supply Chain Integrity, Transparency, and Trust*) & **[RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)** (*COSE*) | Standardizes countersigned transparency receipts so offline auditors can verify that a signed statement was ingested within its valid time window. |

---

## 2. Where This Framework Bridges Gaps in Existing Standards

### Gap 1: Eliminating the "OAuth Redirect Tax" for Tier 1 HITL
* **Limitation of Existing Standards (`RFC 9470` + `RFC 9396 RAR` + `OIDC`):**
  In standard OAuth, every time a resource server requires user consent over rich transaction details (`RAR`), the client must redirect the user to the Authorization Server (or trigger an out-of-band CIBA push notification). In interactive AI agent workflows where an operator may review dozens of actions per hour, full IdP redirects for baseline approvals create severe UX friction.
* **How PoI Bridges the Gap:**
  By issuing an **RFC 7800 `cnf` Ephemeral Key Certificate** at login and maintaining it via **PoP Key Chaining**, the Frontend Signing Vault can cryptographically sign service-issued challenges locally in a single click -- requiring **zero IdP round-trips** for Tier 1 actions while preserving a full cryptographic chain of trust back to the IdP root key.

### Gap 2: Authoritative Human Modifications (`SUPERCEDE` Chaining)
* **Limitation of Existing Standards (`RAR`, `CIBA`, `WebAuthn SPC`):**
  Existing transaction-authorization standards model human interaction as a strictly **binary decision (`Approve` or `Deny`)** over a static proposal. If a human operator wants to adjust a parameter (e.g., changing a dosage or adjusting a loan amount), the protocol treats the transaction as failed and forces the calling application or AI agent to start a new request from scratch.
* **How PoI Bridges the Gap:**
  PoI models human modifications as a first-class, hash-linked state transition: `SUPERCEDE(H0) -> H1`. This provides:
  1. **Direct Execution Without Re-Invoking the LLM:** The human's signed assertion `R1` can be committed directly by the downstream service without risking agent hallucination on retry.
  2. **Multi-Tier Organizational Escalation (`R0 -> R1 -> R2`):** If `R1` exceeds the first human's organizational authority, the hash-linked chain carries cryptographic proof of both the original proposal (`R0`) and the first human's attested adjustment and justification (`R1`) to the next-line approver (`R2`).
