# Cryptographic Proof-of-Intent (PoI) Framework for HITL Workflows

An open architectural framework for recording **Human-in-the-Loop (HITL) step-up approvals and modifications** with auditable, tamper-resistant cryptographic proof of human intent -- designed primarily for high-consequence AI agent workflows (e.g., medication prescriptions, loan originations, infrastructure mutations).

---

## 1. Motivation & Core Problem

As autonomous AI agents increasingly initiate actions against high-consequence domain services, traditional session cookies and bearer tokens fail to distinguish between:
1. **An action autonomously proposed by an AI agent** (which may be hallucinating, prompt-injected, or acting as a confused deputy), and
2. **An action explicitly reviewed, approved, or modified by an authorized human.**

At the same time, forcing high-friction multi-factor prompts or OAuth redirects on every routine HITL interaction introduces unacceptable cognitive overhead and alert fatigue.

### Core Design Goals
* **Zero Extra Cognitive Overhead at Baseline (Tier 1):** Routine HITL approvals require only a single click in the UI, backed by a short-lived, client-generated asymmetric key certified at login (`[nbf, exp]`).
* **Seamless Step-Up for High-Consequence Actions (Tiers 2 & 3):** Downstream services can dynamically demand biometric verification (Platform WebAuthn) or physical hardware token attestation (YubiKey / Cross-Platform WebAuthn) within the exact same cryptographic envelope format.
* **Authoritative Human Modifications (`SUPERCEDE`):** When a human modifies parameters proposed by an agent, the edit is recorded as an immediate superceding of the prior state and a signed assertion of a new state (`R0 -> R1`), escalating via a hash-linked chain (`R1 -> R2`) if the adjustment exceeds the first human's organizational authority.
* **Strict Orthogonality to Policy & State Locking:** Cryptographic validity of human intent is strictly decoupled from organization-specific policy engines (OPA, Cedar, domain logic) and concurrency/locking mechanisms.

---

## 2. Threat Model

| Threat Vector | How the PoI Framework Mitigates It |
| :--- | :--- |
| **Confused Deputy (Prompt-Injected Agent)** | Downstream services -- not the AI agent -- govern action consequence levels, resolve raw IDs into human-readable `display_facts`, and issue signed challenges (`svc_sig`). Once a human asserts/approves a state, execution bypasses the LLM. |
| **Man-in-the-Middle (MITM) & UI Spoofing** | Mutual signing: the frontend verifies the Downstream Service's signature on the challenge (`display_facts` + `raw_params_hash`) before rendering; the service verifies the user's signature over that exact challenge. |
| **Database & Audit Log Tampering** | Pre-execution DB tampering invalidates the payload hash signed by the user. Post-execution tampering is prevented by storing the self-contained chain of signatures (`svc_sig` + `idp_cert` + `user_sig` + `receipt_sig`). |
| **Key Smuggling & Signing Oracle Abuse** | Ephemeral private keys are generated client-side via Web Crypto with `extractable: false` inside an isolated cross-origin signing vault (`vault.example.com`) and rotated via Proof-of-Possession (PoP) key chaining. |
| **Backdated Audit Forgery** | Upon verifying a signature within the active `[nbf, exp]` key window, the receiving service (or transparency log) countersigns a timestamped receipt. |
| **Async Data Drift (TOCTOU)** | Separates asynchronous **Intent Escrowing** (when an agent queues work) from synchronous **Just-in-Time Challenge Minting** (when the approver opens the item). |

---

## 3. Repository Structure

* **[`draft-williams-oauth-poi-core-00.md`](./draft-williams-oauth-poi-core-00.md)** -- **IETF Internet-Draft (Part 1: Core Protocol)**: *"Cryptographic Proof-of-Intent (PoI) Core Protocol for Human-in-the-Loop (HITL) Step-Up Authorization"*. Specifies the stateless two-node (`[R0, R1]`) foundation: Ephemeral Intent Key (EIK) lifecycle, RFC 7800 Key Certification Tokens (`KCT`), PoP Key Chaining Rotation, Resource Server Intent Challenge Objects (`ICO`), RFC 8785 (JCS) canonical hashing, Tier 1/2/3 assurance bindings, stateless verification, Countersigned Intent Receipts (`CIR`), and the 19 core error codes.
* **[`draft-williams-oauth-poi-chained-state-00.md`](./draft-williams-oauth-poi-chained-state-00.md)** -- **IETF Internet-Draft (Part 2: Chained State & Concurrency Extension)**: *"Proof-of-Intent (PoI) Chained State, Multi-Party Escalation, and Concurrency Extension"*. Extends PoI Core for stateful workflows: asynchronous Intent Escrowing vs. Just-in-Time Challenge Minting (TOCTOU protection), multi-hop `SUPERCEDE` escalation chains (`R0 -> R1 -> ... -> Rn`), Linear Chain Compare-and-Swap (CAS) concurrency resolution for competing approvers, and the 4 extension error codes (`authority_escalation_required`, `stale_head_conflict`, `intent_already_finalized`, `context_state_drifted`).
* **[`ARCHITECTURE.md`](./ARCHITECTURE.md)** -- Detailed architectural specification: actors, trust boundaries, ephemeral key lifecycle, Proof-of-Possession key rotation, async HITL flows, and the `SUPERCEDE` escalation state machine.
* **[`PROTOCOL_AND_WIRE_FORMAT.md`](./PROTOCOL_AND_WIRE_FORMAT.md)** -- Concrete JSON/JOSE wire formats, certificate schemas, hash-chaining specifications, Tier 1/2/3 attestation payloads, and the deterministic verification algorithm.
* **[`STANDARDS_AND_RFCS.md`](./STANDARDS_AND_RFCS.md)** -- Mapping of the framework to existing IETF RFCs (`RFC 7800`, `RFC 9449`, `RFC 9470`, `RFC 9396`, `SCITT`, `TraTs`), W3C `WebAuthn`, and `OIDC CIBA`, highlighting where this framework bridges gaps in current standards.
* **[`IETF_SUBMISSION_GUIDE.md`](./IETF_SUBMISSION_GUIDE.md)** -- Step-by-step playbook for compiling the Markdown drafts to RFCXML v3 (`kramdown-rfc` + `xml2rfc`), validating with `idnits`, uploading to the IETF Datatracker, and socializing with the `oauth@ietf.org` Working Group.
* **[`LICENSE.md`](./LICENSE.md)** -- IETF Trust Legal Provisions (BCP 78 / RFC 5378) for specification prose and Revised BSD License (BSD-3-Clause) for code components, JSON schemas, and examples.
* **[`CONTRIBUTING.md`](./CONTRIBUTING.md)** -- Contributor guidelines, IETF Note Well (BCP 78 / BCP 79 / RFC 8874), and ASCII validation instructions.
