---
title: "Proof-of-Intent (PoI) Chained State, Multi-Party Escalation, and Concurrency Extension"
abbrev: "PoI Chained State"
docname: draft-williams-oauth-poi-chained-state-00
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
  - Multi-Party Authorization
  - Concurrency
  - Mandrel

author:
  - ins: P. C. Williams
    name: Paul Charles Williams
    org: Barefoot Coders, LLC
    abbrev: Barefoot Coders
    email: paul@barefootcoders.com
    uri: https://mandrelproject.ai

normative:
  POI-CORE:
    title: "Cryptographic Proof-of-Intent (PoI) Core Protocol for Human-in-the-Loop (HITL) Step-Up Authorization"
    author:
      - ins: P. C. Williams
        name: Paul Charles Williams
        org: Barefoot Coders, LLC
    date: 2026-10
    seriesinfo:
      Internet-Draft: draft-williams-oauth-poi-core-00
  RFC2119:
  RFC7515:
  RFC7519:
  RFC8174:
  RFC8785:
  RFC9457:

informative:
  RFC9635:
  I-D.ietf-scitt-architecture:

--- abstract

The Proof-of-Intent (PoI) Core Protocol (draft-williams-oauth-poi-core-00) specifies a stateless, two-node (`[R0, R1]`) cryptographic framework for verifying synchronous Human-in-the-Loop (HITL) approvals, rejections, and single-hop parameter modifications. However, high-consequence enterprise workflows -- such as multi-tier loan underwriting, dual-control clinical orders, and asynchronous batch agent queues -- frequently require asynchronous review, hierarchical escalation when a human modification exceeds the first operator's organizational authority, and deterministic conflict resolution when multiple approvers act concurrently.

This document extends PoI Core to define: (1) an asynchronous operating mode separating Intent Escrowing from Just-in-Time Challenge Minting to eliminate Time-of-Check to Time-of-Use (TOCTOU) state drift; (2) multi-hop hash-linked assertion chains (R0 -> R1 -> ... -> Rn) supporting hierarchical SUPERCEDE escalations and multi-party co-signatures; (3) a Linear Chain Compare-and-Swap (CAS) concurrency model on head_node_hash that resolves races between competing approvers without ambiguous tree forks; and (4) extended verification rules (including bounded chain length DoS protection) and concurrency error codes.

--- middle

# Introduction

## Motivation for Stateful and Multi-Hop PoI Workflows

{{POI-CORE}} defines the stateless, two-node (`[R0, R1]`) Proof-of-Intent protocol, which satisfies synchronous, single-approver Human-in-the-Loop (HITL) interactions. However, complex enterprise deployments introduce three additional requirements that exceed a two-node stateless model:

1. **Asynchronous Approval Queues:** An autonomous agent may prepare a batch of proposed actions (e.g., loan underwriting packages or clinical refill orders) hours before a human reviewer logs in. Issuing a long-lived challenge at proposal time exposes the system to Time-of-Check to Time-of-Use (TOCTOU) data drift.
2. **Hierarchical Escalation of Human Modifications (`R0 -> R1 -> R2`):** When a human operator modifies parameters via a `SUPERCEDE` assertion (`R1`), the new parameters may exceed that operator's organizational authority limit, requiring escalation to a next-line approver (`R2`) who must cryptographically verify both the original agent proposal (`R0`) and the first operator's signed adjustment and justification (`R1`).
3. **Concurrent Approver Race Conditions:** Multiple authorized approvers may inspect a queued intent simultaneously and submit competing transitions against the same parent node (e.g., Approver 1 submits `APPROVE H0` while Approver 2 submits `SUPERCEDE H0`).

## Relationship to PoI Core and Orthogonality

This document normatively extends {{POI-CORE}}. All Ephemeral Intent Key (EIK), Key Certification Token (`application/poi+jwt;kind=kct`), PoP Key Chaining Rotation (`application/poi+jwt;kind=roll`), JCS canonical hashing ({{RFC8785}}), Assurance Tier (`session-pop`, `webauthn-uv`, `webauthn-hw`), and Countersigned Intent Receipt (`application/poi+jwt;kind=rcpt`) specifications from {{POI-CORE}} apply unchanged.

Consistent with {{POI-CORE}}, organizational policy rules (such as which dollar amount or medication class triggers escalation) and domain record locking strategies remain strictly orthogonal to PoI cryptographic verification.


# Conventions and Terminology

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ({{RFC2119}}, {{RFC8174}}) when, and only when, they appear in all capitals, as shown here.

## Terminology

In addition to the terms defined in Section 2.2 of {{POI-CORE}}, this specification uses the following terms:

* **Escrowed Intent:** A proposed transaction (`R0`) or partially approved chain (`[R0, ..., Rk]`) persisted by a Resource Server in a non-terminal pending state awaiting asynchronous human review or next-line escalation.
* **Head Node Hash (`head_node_hash`):** The `node_hash` (`Hk`) of the latest verified node (`seq: k`) in an Escrowed Intent's `chain` on the Resource Server.
* **Linear Chain Compare-and-Swap (CAS):** The atomic state transition rule requiring any candidate node at `seq: k + 1` to reference the Resource Server's current `head_node_hash` (`Hk`) as its parent hash.


# Asynchronous Operating Mode (Escrowing and Just-in-Time Minting)

## The Stale Challenge and TOCTOU Problem

In asynchronous workflows, hours or days may elapse between when an AI agent proposes an action (`t0`) and when a human approver reviews it (`t1`). If the Resource Server mints a signed Intent Challenge Object (ICO) at `t0` with a multi-day expiration window:
1. Underlying domain state (e.g., patient lab results, allergy records, or borrower credit flags) may change between `t0` and `t1` (TOCTOU drift).
2. A long-lived challenge creates an unnecessarily wide replay and tampering window.

To prevent TOCTOU drift while keeping cryptographic validity windows tight, Resource Servers supporting asynchronous HITL MUST split **Intent Escrowing** from **Just-in-Time Challenge Minting**.

## Stage 1: Asynchronous Intent Escrowing

At `t0` (when the autonomous agent invokes the Resource Server without an active human session):
1. The Resource Server validates the proposed parameters, computes a snapshot digest of relevant domain state (`context_state_hash`), and stores the proposal in `PENDING_APPROVAL` state under a unique `intent_id`.
2. The Resource Server returns HTTP `202 Accepted` (or `403 Forbidden` with `PoI-Challenge: error="intent_proof_required", intent_id="..."`) to the agent without minting a long-lived ICO.

## Stage 2: Just-in-Time Challenge Minting

At `t1` (when an authorized human approver logs in with an active KCT and opens `intent_id` from their approval queue):
1. The client requests the challenge for `intent_id` from the Resource Server.
2. **State Freshness Evaluation:** The Resource Server verifies that the underlying domain state still matches `context_state_hash` (or re-computes `display_facts` against current state).
3. The Resource Server mints a **fresh, short-lived ICO** (`typ: "poi+jwt;kind=chal"`, `nbf: t1`, `exp: t1 + 300s`) bound to `intent_id` and `context_state_hash`.

## Stage 3: Synchronous Signing and Role Separation

The approver reviews the freshly minted ICO inside the Signing Vault and signs `R1` using their currently active KCT (or WebAuthn credential).

Because the ICO is minted at `t1` and signed under the approver's active KCT at `t1`, this flow naturally supports **role separation (dual control)**: the user or service account under which the AI agent proposed `R0` at `t0` MAY be distinct from the authorized human (`sub` in `R1`'s KCT) who approves or supercedes `R0` at `t1`.


# Multi-Hop Hash-Linked Chains (`R0 -> R1 -> ... -> Rn`)

## General `n`-Node Envelope Structure and Transport Sizing

In the Chained State profile, a Proof-of-Intent Envelope (`application/poi-envelope+json`) carries an ordered `chain` of `n + 1` nodes (`seq: 0 ... n`, where `1 <= n < MAX_CHAIN_LENGTH`).

Because multi-node chains (`n >= 2`) containing nested `kcert` JWTs and WebAuthn assertions can exceed the 4 KB to 8 KB HTTP header limit enforced by reverse proxies, implementations SHOULD transmit multi-node PoIEs in the HTTP request body (`Content-Type: application/poi-envelope+json`) rather than the `PoI-Envelope` HTTP header, or use detached mode for `R0` (omitting `challenge_jws` when the stateful Resource Server already holds `[R0, ..., R_(n-1)]` in escrow).

~~~json
{
  "intent_id": "intent_loan_4409",
  "chain": [
    {
      "seq": 0,
      "node_type": "PROPOSAL",
      "challenge_jws": "<Compact-JWS-from-Resource-Server>",
      "node_hash": "sha256:H0_8f992a..."
    },
    {
      "seq": 1,
      "node_type": "SUPERCEDE",
      "supercedes_node_hash": "sha256:H0_8f992a...",
      "assurance_tier": "urn:ietf:params:oauth:poi:tier:session-pop",
      "assertion_jws": "<Compact-JWS-Signed-by-Loan-Officer>",
      "node_hash": "sha256:H1_3c771b..."
    },
    {
      "seq": 2,
      "node_type": "APPROVE",
      "target_node_hash": "sha256:H1_3c771b...",
      "assurance_tier": "urn:ietf:params:oauth:poi:tier:webauthn-uv",
      "assertion_jws": "<WebAuthn-Bundle-Signed-by-Sr-Underwriter>",
      "node_hash": "sha256:H2_9a110f..."
    }
  ]
}
~~~

## Three Outcomes of a `SUPERCEDE` Assertion

When a human signer submits a `SUPERCEDE` node (`Rk`) asserting modified parameters (`asserted_params`), the Resource Server's orthogonal policy engine evaluates `asserted_params` and selects one of three deterministic transitions:

1. **Outcome 1 -- Sufficient Authority and Assurance (Immediate Execution):**
   * The signer of `Rk` possesses organizational authority for `asserted_params`, and `Rk` satisfies the required assurance tier for those parameters.
   * The Resource Server commits `asserted_params` immediately and issues a terminal Countersigned Intent Receipt (`CIR`).
2. **Outcome 2 -- Same Signer Has Authority, Higher Assurance Tier Required (Step-Up Challenge):**
   * `asserted_params` is within the signer's organizational role authority, but the modified value crosses into a higher assurance requirement (for example, a physician modifies a prescription from a non-controlled drug at Tier 1 `session-pop` to a Schedule II controlled substance requiring Tier 3 `webauthn-hw`).
   * The Resource Server returns HTTP `403 Forbidden` with `PoI-Challenge: error="insufficient_assurance_tier", required_tier="urn:ietf:params:oauth:poi:tier:webauthn-hw"`, and a step-up challenge targeting `Hk` so the same signer can immediately complete hardware token attestation.
3. **Outcome 3 -- Organizational Authority Exceeded (Chained Escalation):**
   * `asserted_params` exceeds the signer's organizational policy limit (for example, a loan officer adjusts a loan from `"45000.00"` to `"60000.00"`, exceeding their `"50000.00"` underwriting limit).
   * The Resource Server records `[R0, ..., Rk]` as `PENDING_ESCALATION` with `head_node_hash = Hk`, returns HTTP `202 Accepted` (or `403 Forbidden` with `poi_error: "authority_escalation_required"`), and routes the escalated intent to the next-line authority queue.

## Chained Escalation Challenge Format

When a next-line approver opens an escalated intent at `head_node_hash = Hk`, the Resource Server mints an ICO (`typ: "poi+jwt;kind=chal"`) that includes a `prior_chain` claim containing the verified predecessor nodes `[R0, ..., Rk]` alongside the computed parameter delta in `display_facts`.

The next-line approver's Signing Vault MUST verify the Resource Server's ICO signature and render:
1. The original proposal (`R0`),
2. Each intermediate `SUPERCEDE` modification, diff, and human justification (`R1 ... Rk`), and
3. The verified identity of each prior human signer, before prompting the next-line approver to sign Node `R_(k+1)` (`APPROVE` targeting `Hk`, or another `SUPERCEDE` targeting `Hk`).


# Concurrent Approver Race Conditions (Linear Chain Compare-and-Swap)

## Linear Chain CAS Invariant on `head_node_hash`

In multi-operator environments, two authorized approvers (Approver 1 and Approver 2) may concurrently inspect a pending intent at `head_node_hash = Hk` (`seq: k`) and submit competing transitions for `seq: k + 1` -- for example, Approver 1 submits `R_(k+1)_A` (`APPROVE` targeting `Hk`) while Approver 2 submits `R_(k+1)_B` (`SUPERCEDE` targeting `Hk`).

To prevent ambiguous forked trees and ensure a single linear audit history, Resource Servers MUST enforce an atomic **Linear Chain Compare-and-Swap (CAS) Invariant**:

* A Resource Server MUST only accept and append a candidate node at `seq: k + 1` if:
  1. Its parent hash reference (`target_node_hash` or `supercedes_node_hash`) is byte-identical to the Resource Server's current `head_node_hash` (`Hk` at `seq: k`), AND
  2. The intent has not already reached a terminal state (`COMMITTED` or `REJECTED`).
* Upon accepting `R_(k+1)`, the Resource Server atomically updates `head_node_hash` from `Hk` to `H_(k+1)`.

## Prohibition on Silent Rebase

Intermediary agents, orchestrators, and Resource Servers MUST NOT rewrite a losing assertion's parent hash reference from `Hk` to `H_(k+1)` in flight. Because `target_node_hash` and `supercedes_node_hash` are covered by the human signer's cryptographic signature, rewriting the parent pointer invalidates the signature and violates What You See Is What You Sign (WYSIWYS), as the losing signer never reviewed the intervening transition `R_(k+1)`.

## Arrival Order 1: `SUPERCEDE` Arrives Before `APPROVE`

~~~text
t = 100ms: Approver 2 submits R1_B (SUPERCEDE H0 -> new params P1)
           RS CAS succeeds: head_node_hash advances H0 -> H1_B.

t = 150ms: Approver 1 submits R1_A (APPROVE H0)
           RS CAS FAILS: parent H0 != current head H1_B.
~~~

1. If `R1_B` was within Approver 2's authority and executed immediately at `t = 100ms`, the Resource Server MUST reject Approver 1's `R1_A` with HTTP `409 Conflict` (`poi_error: "intent_already_finalized"`), returning the terminal `CIR`.
2. If `R1_B` remains pending (e.g., awaiting co-signature or escalation), the Resource Server MUST reject `R1_A` with HTTP `409 Conflict` (`poi_error: "stale_head_conflict"`), returning the updated chain `[R0, R1_B]`. Approver 1's Signing Vault renders Approver 2's modification (`R1_B`) and justification so Approver 1 can consciously sign `R2` (`APPROVE H1_B`) if authorized.

## Arrival Order 2: `APPROVE` Arrives Before `SUPERCEDE`

~~~text
t = 100ms: Approver 1 submits R1_A (APPROVE H0)
           RS CAS succeeds: head_node_hash advances H0 -> H1_A.

t = 150ms: Approver 2 submits R1_B (SUPERCEDE H0 -> new params P1)
           RS CAS FAILS: parent H0 != current head H1_A.
~~~

1. **Single-Approver Policy (Already Executed at `t = 100ms`):**
   * If `R1_A` satisfied the Resource Server's policy and triggered immediate execution at `t = 100ms`, the Resource Server MUST reject Approver 2's `R1_B` with HTTP `409 Conflict` (`poi_error: "intent_already_finalized"`), returning `[R0, R1_A]` and the `CIR`.
2. **Multi-Approver / Quorum Policy (Still Pending at `H1_A`):**
   * If the intent requires multiple approvals (e.g., 2-of-2 quorum) and remains pending at `head_node_hash = H1_A` after Approver 1's signature, the Resource Server MUST reject Approver 2's `R1_B` with HTTP `409 Conflict` (`poi_error: "stale_head_conflict"`), returning `[R0, R1_A]`.
   * Approver 2's Signing Vault alerts Approver 2 that Approver 1 approved `R0` (`H1_A`), preserves Approver 2's edited parameter values in the UI, and prompts Approver 2 to sign their modification against the new head `H1_A`.
   * The resulting linear chain `R0 -> R1_A (APPROVE H0) -> R2 (SUPERCEDE H1_A)` preserves exact chronological audit provenance: it proves Approver 1 approved `R0`, and Approver 2 subsequently superceded Approver 1's approval with new parameters `P1` (which invalidates Approver 1's prior approval of `R0` and requires quorum approval over `H2`).


# Extended Multi-Node Verification Algorithm

A Resource Server or offline verifier validating a multi-node PoIE (`chain[0 ... n]`, where `n >= 1`) MUST execute the following steps:

1. **Enforce Bounded Chain Length (`MAX_CHAIN_LENGTH`):**
   * Before performing any cryptographic operations, confirm `2 <= length(chain) <= MAX_CHAIN_LENGTH` (where the RECOMMENDED default for `MAX_CHAIN_LENGTH` is `16`). If `length(chain)` exceeds `MAX_CHAIN_LENGTH`, fail immediately with HTTP `400 Bad Request` (`malformed_poi_envelope`).
2. **Validate Root Proposal (`R0`):**
   * Execute Step 1 of Section 7.1 of {{POI-CORE}} to verify `chain[0].challenge_jws` and confirm `chain[0].node_hash == H0`.
3. **Iterate Through Chain Nodes (`i = 1 ... n`):**
   * Confirm `chain[i].seq == i`.
   * Confirm `chain[i]`'s parent hash reference (`target_node_hash` for `APPROVE`/`REJECT`, or `supercedes_node_hash` for `SUPERCEDE`) equals `chain[i-1].node_hash` (`H_(i-1)`).
   * Confirm `assertion.aud == ico.iss`.
   * If `chain[i].node_type == "REJECT"` and `i < n`, fail verification with `chain_continuity_broken` (a `REJECT` node is strictly terminal and MUST NOT have child nodes).
   * If `chain[i].node_type == "SUPERCEDE"`, recompute `SHA-256(JCS(asserted_params))` over the raw JSON tree and confirm it matches `asserted_params_hash`.
   * Verify `chain[i]`'s cryptographic signature and assurance tier (`session-pop`, `webauthn-uv`, or `webauthn-hw`) per Step 3 of Section 7.1 of {{POI-CORE}}.
   * Confirm `chain[i].node_hash` matches the canonical SHA-256 digest of node `i`.
4. **Determine Effective Parameter State and Active Signers:**
   * Let `k_last_supercede` be the largest index `k` (`1 <= k <= n`) where `chain[k].node_type == "SUPERCEDE"`, or `0` if no `SUPERCEDE` node exists in `chain`.
   * The **effective parameters** of the chain are `chain[k_last_supercede].asserted_params` (if `k_last_supercede >= 1`) or `R0.raw_params` (if `k_last_supercede == 0`).
   * **Important Quorum Rule:** Any `APPROVE` node at index `j < k_last_supercede` attested to parameters that were subsequently superceded at index `k_last_supercede`. Therefore, when evaluating multi-approver quorum or escalation authority for the effective parameters, the policy engine MUST only count signers at indices `i >= k_last_supercede`.


# Chained State and Concurrency Error Modes

## Escalation and Concurrency Error Definitions

In addition to the 19 core error codes defined in Section 8 of {{POI-CORE}}, this extension defines four error codes for stateful, asynchronous, and multi-party workflows:

* **`authority_escalation_required`** (HTTP `202 Accepted` or `403 Forbidden`):
  * *Trigger:* A verified `SUPERCEDE` assertion (`Rk`) asserts parameters that exceed the signer's organizational policy limit (Section 4.2 Outcome 3). When queued asynchronously for next-line approval, the Resource Server SHOULD return `202 Accepted` with `"poi_status": "pending_escalation"`; when synchronous multi-party approval is required, the Resource Server MUST return `403 Forbidden` with `PoI-Challenge: error="authority_escalation_required"`.
* **`stale_head_conflict`** (HTTP `409 Conflict`):
  * *Trigger:* A candidate node at `seq: k + 1` failed the Linear Chain Compare-and-Swap check because a concurrent signer already advanced the Resource Server's `head_node_hash` for `intent_id` from `Hk` to `H_(k+1)` while the intent remains open (Section 5.1). The {{RFC9457}} problem details body MUST include `current_head_node_hash` and the updated `chain` array (`[R0, ..., R_(k+1)]`) so the client Signing Vault can render the intervening transition and prompt the user against `H_(k+1)`.
* **`intent_already_finalized`** (HTTP `409 Conflict`):
  * *Trigger:* A candidate node arrived after a concurrent signer's `APPROVE`, `REJECT`, or authoritative `SUPERCEDE` assertion already transitioned `intent_id` into a terminal executed or rejected state (`CIR` issued). The problem details body SHOULD include the terminal `CIR`.
* **`context_state_drifted`** (HTTP `409 Conflict`):
  * *Trigger:* In asynchronous flows (Section 3), the underlying domain record on the Resource Server changed between when the proposal or challenge was created (`context_state_hash`) and when the PoIE was submitted for execution (TOCTOU violation).

*Non-normative example of a `stale_head_conflict` Problem Details response:*

~~~http
HTTP/1.1 409 Conflict
Content-Type: application/problem+json

{
  "type": "urn:ietf:params:oauth:poi:error:stale_head_conflict",
  "title": "Concurrent Approver Modified Chain Head",
  "status": 409,
  "detail": "Candidate seq 1 references H0, but head is H1_B.",
  "poi_error": "stale_head_conflict",
  "intent_id": "intent_loan_4409",
  "failed_node_seq": 1,
  "current_head_node_hash": "sha256:H1_3c771b...",
  "chain": [
    {
      "seq": 0,
      "node_type": "PROPOSAL",
      "node_hash": "sha256:H0_8f992a..."
    },
    {
      "seq": 1,
      "node_type": "SUPERCEDE",
      "supercedes_node_hash": "sha256:H0_8f992a...",
      "node_hash": "sha256:H1_3c771b..."
    }
  ]
}
~~~

## Summary Matrix of Extension Error Codes

| `poi_error` Code | Category | HTTP Status | Retryable with New Signature? |
| :--- | :--- | :--- | :--- |
| `authority_escalation_required` | Escalation | `202` / `403` | Yes (Next-line approver appends `R_(k+1)`) |
| `stale_head_conflict` | Concurrency / CAS | `409` | Yes (Review new head `H_(k+1)` and re-sign) |
| `intent_already_finalized` | Concurrency / Terminal | `409` | No (Intent already executed or rejected) |
| `context_state_drifted` | State / TOCTOU | `409` | Yes (Fetch re-evaluated challenge) |


# Security Considerations

## Time-of-Check to Time-of-Use (TOCTOU) Mitigation

In asynchronous workflows, Resource Servers MUST NOT issue long-lived ICO challenges at proposal time (`t0`). Resource Servers MUST bind `context_state_hash` when minting the just-in-time ICO at review time (`t1`) and re-verify `context_state_hash` atomically when committing the terminal node of the PoIE.

## Lineage Integrity Across Escalation Hops

In multi-party escalations (`R0 -> R1 -> R2`), a compromised intermediary orchestrator might attempt to strip `R1` or alter the first human's justification to influence the next-line approver (`R2`). Because `H1` commits to the entire signed `R1` assertion JWS (including `asserted_params_hash` and `justification`) and the Resource Server's escalation ICO signs `prior_chain: [R0, R1]`, any tampering with intermediate nodes invalidates both the hash chain and the Resource Server's challenge signature.

Furthermore, per Step 4 of Section 6, verifiers MUST NOT count `APPROVE` signatures at indices `j < k_last_supercede` toward quorum requirements for parameters modified at `k_last_supercede`, preventing an attacker or confused policy engine from treating a prior approval of `R0` as an approval of modified parameters in `Rk`.

## Denial-of-Service Mitigation via Bounded Chain Depth

Because verifying each node in `chain` requires up to two asymmetric public-key signature verifications (`kcert` and `assertion_jws`), an unbounded `chain` array would allow a malicious client to cause CPU exhaustion by submitting thousands of self-superceding nodes in a single request. Verifiers MUST enforce `MAX_CHAIN_LENGTH` (Section 6 Step 1) prior to executing any cryptographic signature checks.


# IANA Considerations

## PoI Error Code Registrations

This document registers four additional error codes in the "Proof-of-Intent (PoI) Error Codes" registry (`urn:ietf:params:oauth:poi:error`) established in Section 11.3 of {{POI-CORE}}:

* `authority_escalation_required` (Section 7.1)
* `stale_head_conflict` (Section 7.1)
* `intent_already_finalized` (Section 7.1)
* `context_state_drifted` (Section 7.1)

## JWT Claim Registrations

This document registers the following claims in the IANA "JSON Web Token Claims" registry ({{RFC7519}}):

* `context_state_hash`: Digest of the Resource Server's underlying domain state at challenge issuance time (Section 3.2).
* `prior_chain`: Ordered array of verified predecessor PoIE nodes included in an escalated Intent Challenge Object (Section 4.3).
* `current_head_node_hash`: The `node_hash` of the current head node on the Resource Server returned in a `stale_head_conflict` error response (Section 7.1).
