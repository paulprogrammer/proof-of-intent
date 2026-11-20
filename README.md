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
* **Uniform Step-Up for High-Consequence Actions (Tiers 2 & 3):** Downstream services can dynamically demand biometric verification (Platform WebAuthn), PSEA confirmation tokens, or physical hardware token attestation (Cross-Platform WebAuthn) within the same cryptographic envelope format.
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

* **[`draft-williams-oauth-poi-core-01.md`](./draft-williams-oauth-poi-core-01.md)** -- **IETF Internet-Draft (Part 1: Core Protocol, active `-01`)**: *"Cryptographic Proof-of-Intent (PoI) Core Protocol for Human-in-the-Loop (HITL) Step-Up Authorization"*. Normative specification for Ephemeral Intent Keys (EIK), RFC 7800 Key Certification Tokens (`KCT`), PoP key rotation, Resource Server Intent Challenge Objects (`ICO`), RFC 8785 (JCS) canonical hashing and node hashes, the `attestation` container, Tier 1/2/3 assurance profiles (session key, PSEA, WebAuthn), stateless evidence verification plus stateful consume-once admission, Countersigned Intent Receipts (`CIR`), recovery from unknown outcomes, and the 20 core error codes. (`draft-williams-oauth-poi-core-00.md` remains frozen as the published historical `-00` revision.)
* **[`draft-williams-oauth-poi-chained-state-01.md`](./draft-williams-oauth-poi-chained-state-01.md)** -- **IETF Internet-Draft (Part 2: Chained State & Concurrency Extension, active `-01`)**: *"Proof-of-Intent (PoI) Chained State, Multi-Party Escalation, and Concurrency Extension"*. Extends PoI Core for stateful multi-hop workflows: asynchronous Intent Escrowing vs. Just-in-Time Challenge Minting (TOCTOU protection), multi-hop `SUPERCEDE` and quorum chains (`R0 -> R1 -> ... -> Rn`) with per-node challenge binding, atomic Linear Chain Compare-and-Swap (CAS) concurrency control, and the 4 extension error codes (`authority_escalation_required`, `stale_head_conflict`, `intent_already_finalized`, `context_state_drifted`). (`draft-williams-oauth-poi-chained-state-00.md` remains frozen as the published historical `-00` revision.)
* **[`ARCHITECTURE.md`](./ARCHITECTURE.md)**, **[`PROTOCOL_AND_WIRE_FORMAT.md`](./PROTOCOL_AND_WIRE_FORMAT.md)**, and **[`STANDARDS_AND_RFCS.md`](./STANDARDS_AND_RFCS.md)** -- Initial architecture, wire-format background, and RFC mapping notes; the `-01` Internet-Drafts above are normative.
* **[`Makefile`](./Makefile)** -- Compiles RFCXML v3, paginated TXT, HTML, and PDF deliverables from the Markdown drafts and validates them with `idnits`.
* **[`scripts/verify-poi.sh`](./scripts/verify-poi.sh)** -- Cross-submodule verification gate covering `mandrel-spec`, `mandrel-go`, `mandrel-collet`, `mandrel-cli`, and `mandrel-demo` (`DEMO=1` runs the Podman end-to-end PoI suite).
* **[`TODO.md`](./TODO.md)** -- Active work tracker for specification and implementation items.
* **Reference implementation submodules** (see [`CONTRIBUTING.md`](./CONTRIBUTING.md) Section 3): `mandrel-go` (Go verifier library), `mandrel-collet` (enforcement sidecar), `mandrel-demo` (mock IdP, mock Signing Vault, end-to-end demo scripts), `mandrel-spec` (schemas, protos, normative vectors), and `mandrel-cli` (validator and Rego generator).
* **[`LICENSE.md`](./LICENSE.md)** -- IETF Trust Legal Provisions (BCP 78 / RFC 5378) for specification prose and Revised BSD License (BSD-3-Clause) for code components, JSON schemas, and examples.
* **[`CONTRIBUTING.md`](./CONTRIBUTING.md)** -- Contributor guidelines, IETF Note Well (BCP 78 / BCP 79 / RFC 8874), ASCII validation instructions, and submodule workflow rules.
