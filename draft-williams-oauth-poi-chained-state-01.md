---
title: "Proof-of-Intent (PoI) Chained State, Multi-Party Escalation, and Concurrency Extension"
abbrev: "PoI Chained State"
docname: draft-williams-oauth-poi-chained-state-01
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
    date: 2026-11
    seriesinfo:
      Internet-Draft: draft-williams-oauth-poi-core-01
  RFC2119:
  RFC7515:
  RFC7519:
  RFC8174:
  RFC8785:
  RFC9457:

informative:
  RFC7942:

--- abstract

The Proof-of-Intent (PoI) Core protocol (draft-williams-oauth-poi-core-01) covers one proposal and one human decision. Some workflows need more: review hours after the agent proposed, escalation when an edit exceeds the first approver's authority, and a rule for approvers acting at the same time.

This document extends PoI Core with: (1) escrow at proposal time and short-lived challenges minted at review time, to avoid stale state; (2) hash-linked chains (R0 -> R1 -> ... -> Rn) for escalation and co-signing, with each appended node bound to its own challenge; (3) a compare-and-swap on the chain head, performed atomically with challenge consumption, so competing approvals cannot fork the chain; and (4) chain verification rules, a chain length limit, and concurrency error codes.

--- middle

# Introduction

## Motivation for Stateful and Multi-Hop PoI Workflows

{{POI-CORE}} handles one approver deciding synchronously. Three cases need more:

1. **Asynchronous queues:** An agent may prepare actions (loan packages, refill orders) hours before a reviewer logs in. A challenge minted at proposal time would sign state that may have changed by review time.
2. **Escalation (`R0 -> R1 -> R2`):** A `SUPERCEDE` (`R1`) may exceed the signer's authority. The next approver (`R2`) needs to see both the agent proposal (`R0`) and the first signer's change and justification (`R1`).
3. **Concurrent approvers:** Two approvers may act on the same node at once (one sends `APPROVE H0`, the other `SUPERCEDE H0`).

## Relationship to PoI Core and Orthogonality

This document extends {{POI-CORE}}. These parts of {{POI-CORE}} apply unchanged: EIKs and KCTs (`application/poi+jwt;kind=kct`), key rotation (`application/poi+jwt;kind=roll`), JCS hashing ({{RFC8785}}) and node hashes (Section 6.1), the attestation container, tier ordering, preconditions, and profiles (Section 6.3), consume-once admission (Section 7.1, step 5), the CIR (`application/poi+jwt;kind=rcpt`, Section 7.2), and recovery from unknown outcomes (Section 9.4).

As in {{POI-CORE}}, policy (which amounts or drug classes escalate) and record locking stay outside PoI. A Resource Server implementing this extension is stateful: it holds escrowed chains, the `head_node_hash` of each open intent, and the consumed-challenge record.


# Conventions and Terminology

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

## Terminology

Terms from Section 2.2 of {{POI-CORE}} apply. In addition:

* **Escrowed Intent:** A proposal (`R0`) or partial chain (`[R0, ..., Rk]`) held by the RS while it waits for review or escalation.
* **Head Node Hash (`head_node_hash`):** The `node_hash` (`Hk`) of the latest accepted node (`seq: k`) of an escrowed intent.
* **Linear Chain Compare-and-Swap (CAS):** The rule that a candidate node at `seq: k + 1` must name the current `head_node_hash` (`Hk`) as its parent.
* **Node Challenge:** The ICO a node was signed under: the root challenge in `R0` for an un-escalated `R1`, or the challenge minted for that append (Section 4.4).


# Asynchronous Operating Mode (Escrowing and Just-in-Time Minting)

## The Stale Challenge and TOCTOU Problem

Hours or days can pass between the proposal (`t0`) and the review (`t1`). A challenge minted at `t0` with a long expiry has two problems:
1. The underlying records (lab results, allergies, credit flags) may change before `t1`.
2. A long-lived challenge widens the replay window.

An RS that supports asynchronous review MUST separate escrow from challenge minting.

## Stage 1: Asynchronous Intent Escrowing

At `t0`, when the agent calls without a person present:
1. The RS validates the parameters, computes a digest of the relevant domain state (`context_state_hash`), and stores the proposal as `PENDING_APPROVAL` under an `intent_id`. The `intent_id` names the business occurrence and stays the same for every challenge minted for it ({{POI-CORE}} Section 5.2).
2. The RS returns `202 Accepted` (or `403 Forbidden` with `PoI-Challenge: error="intent_proof_required", intent_id="..."`) without minting a long-lived ICO.

## Stage 2: Just-in-Time Challenge Minting

At `t1`, when a reviewer with an active KCT opens the intent:
1. The client requests a challenge for the `intent_id`.
2. The RS checks that domain state still matches `context_state_hash` (or recomputes `display_facts` from current state).
3. The RS mints a short-lived ICO (`typ: "poi+jwt;kind=chal"`, `nbf: t1`, `exp: t1 + 300s`) with a new `challenge_id`, bound to the `intent_id` and `context_state_hash`. Each challenge is consumed at most once ({{POI-CORE}} Section 7.1, step 5).

## Stage 3: Synchronous Signing and Role Separation

The reviewer signs `R1` in the Signing Vault with any {{POI-CORE}} Section 6.3.3 profile that meets the required tier.

Because the challenge is minted and signed at `t1`, the account the agent proposed under at `t0` MAY differ from the person (`sub` of `R1`) who approves or supercedes it. This supports dual control.


# Multi-Hop Hash-Linked Chains (`R0 -> R1 -> ... -> Rn`)

## General `n`-Node Envelope Structure and Transport Sizing

A chained PoIE (`application/poi-envelope+json`) has `n + 1` nodes (`seq: 0 ... n`, `1 <= n < MAX_CHAIN_LENGTH`). Every attestation node uses the {{POI-CORE}} Section 6.3.1 container, and every `node_hash` follows {{POI-CORE}} Section 6.1.

Chains with `n >= 2` that carry KCTs (compact JWS, {{RFC7515}}) and WebAuthn assertions can exceed the 4 to 8 KB header limits of reverse proxies. Implementations SHOULD send them in the request body instead of the `PoI-Envelope` header, or use detached `R0` when the RS already holds `[R0, ..., R_(n-1)]` in escrow.

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
      "attestation": {
        "format": "application/poi+jwt;kind=assert",
        "token": "<Compact-JWS-Signed-by-Loan-Officer>"
      },
      "node_hash": "sha256:H1_3c771b..."
    },
    {
      "seq": 2,
      "node_type": "APPROVE",
      "target_node_hash": "sha256:H1_3c771b...",
      "challenge_jws": "<Escalation-ICO-for-seq-2>",
      "assurance_tier": "urn:ietf:params:oauth:poi:tier:webauthn-uv",
      "attestation": {
        "format": "urn:ietf:params:oauth:poi:attestation:webauthn",
        "token": {
          "assertion_payload": { "...": "..." },
          "credential_id": "...",
          "authenticator_data": "...",
          "client_data_json": "...",
          "signature": "..."
        }
      },
      "node_hash": "sha256:H2_9a110f..."
    }
  ]
}
~~~

## Three Outcomes of a `SUPERCEDE` Assertion

When a signer submits a `SUPERCEDE` node (`Rk`), policy evaluates `asserted_params` and picks one outcome:

1. **Authority and tier sufficient:** The RS admits `Rk` ({{POI-CORE}} Section 7.1, step 5), executes `asserted_params`, and issues a CIR. The CIR records admission; the execution outcome is handled by {{POI-CORE}} Section 9.4.
2. **Authority sufficient, higher tier required:** The edit is within the signer's role but raises the required tier (for example, a prescription changed from a non-controlled drug at Tier 1 to a Schedule II drug at Tier 3). The RS returns `403` with `PoI-Challenge: error="insufficient_assurance_tier", required_tier="urn:ietf:params:oauth:poi:tier:webauthn-hw"` and a step-up challenge for the append at the current head (Section 4.4). The appended node asserts parameters, so its attestation MUST use a profile that commits to `asserted_params_hash`; {{POI-CORE}} Section 6.3.3.2 excludes PSEA for `SUPERCEDE`.
3. **Authority exceeded:** The edit exceeds the signer's limit (for example, a loan raised from `"45000.00"` to `"60000.00"` against a `"50000.00"` limit). The RS records `[R0, ..., Rk]` as `PENDING_ESCALATION` with `head_node_hash = Hk`, returns `202` (or `403` with `poi_error: "authority_escalation_required"`), and routes the intent to the next approver.

## Chained Escalation Challenge Format

When the next approver opens an intent at `head_node_hash = Hk`, the RS mints an ICO with the same `intent_id`, a new `challenge_id`, a `prior_chain` claim holding `[R0, ..., Rk]`, and the parameter changes in `display_facts`.

The approver's Signing Vault MUST verify the ICO signature and show:
1. the original proposal (`R0`);
2. each `SUPERCEDE` change, diff, and justification (`R1 ... Rk`); and
3. who signed each prior node,

before asking the approver to sign `R_(k+1)` (`APPROVE` or `SUPERCEDE` targeting `Hk`).

The vault relies on the RS signature over `prior_chain` for prior signers' identities. It cannot verify Tier 2 or Tier 3 attestations itself, because that needs the RS enrollment records ({{POI-CORE}} Section 6.3.2, precondition 6).

## Challenge Binding for Appended Nodes

{{POI-CORE}} Section 6.3.2, precondition 4, requires each attestation to bind the challenge it answers. In a chain, that is the node's Node Challenge:

* `R1` signed against the root challenge binds the challenge in `R0`.
* A node appended in response to an escalation (Section 4.3) or step-up (Section 4.2, outcome 2) challenge MUST carry that ICO in its `challenge_jws` member. Its attestation MUST bind that ICO's `intent_id` and `challenge_id`, and the ICO's `intent_id` MUST equal `R0`'s.
* The carried ICO's `prior_chain` MUST list exactly the preceding nodes, by `seq` and `node_hash`. This ties the challenge to the head it was minted for.
* Each node's challenge is covered by its `node_hash` ({{POI-CORE}} Section 6.1), so auditors can check it.
* On admission, the RS consumes the appended node's `challenge_id` ({{POI-CORE}} Section 7.1, step 5) in the same atomic operation as the CAS (Section 5.5).


# Concurrent Approver Race Conditions (Linear Chain Compare-and-Swap)

## Linear Chain CAS Invariant on `head_node_hash`

Two approvers may both see an intent at `head_node_hash = Hk` and submit competing nodes for `seq: k + 1` (for example, `R_(k+1)_A` approves `Hk` while `R_(k+1)_B` supercedes it).

To keep one linear history, the RS MUST enforce:

* A node at `seq: k + 1` is accepted only if:
  1. its parent reference (`target_node_hash` or `supercedes_node_hash`) equals the current `head_node_hash` (`Hk`), and
  2. the intent is not terminal (`COMMITTED` or `REJECTED`).
* On acceptance, `head_node_hash` atomically moves from `Hk` to `H_(k+1)`.

## Prohibition on Silent Rebase

Agents, orchestrators, and Resource Servers MUST NOT rewrite a losing node's parent from `Hk` to `H_(k+1)`. Every attestation commits to its parent ({{POI-CORE}} Section 6.3.2, precondition 3), so a rewrite breaks it, and the losing signer never saw `R_(k+1)`.

## Arrival Order 1: `SUPERCEDE` Arrives Before `APPROVE`

~~~text
t = 100ms: Approver 2 submits R1_B (SUPERCEDE H0 -> new params P1)
           RS CAS succeeds: head_node_hash advances H0 -> H1_B.

t = 150ms: Approver 1 submits R1_A (APPROVE H0)
           RS CAS FAILS: parent H0 != current head H1_B.
~~~

1. If `R1_B` executed at `t = 100ms`, the RS MUST reject `R1_A` with `409` (`intent_already_finalized`) and return the CIR.
2. If `R1_B` is still pending (co-signature or escalation), the RS MUST reject `R1_A` with `409` (`stale_head_conflict`) and return `[R0, R1_B]`. Approver 1's vault shows `R1_B` and its justification, so Approver 1 can sign `R2` (`APPROVE H1_B`) under a new challenge.

## Arrival Order 2: `APPROVE` Arrives Before `SUPERCEDE`

~~~text
t = 100ms: Approver 1 submits R1_A (APPROVE H0)
           RS CAS succeeds: head_node_hash advances H0 -> H1_A.

t = 150ms: Approver 2 submits R1_B (SUPERCEDE H0 -> new params P1)
           RS CAS FAILS: parent H0 != current head H1_A.
~~~

1. **Single approver, already executed:** The RS MUST reject `R1_B` with `409` (`intent_already_finalized`) and return `[R0, R1_A]` and the CIR.
2. **Quorum still pending at `H1_A`:** The RS MUST reject `R1_B` with `409` (`stale_head_conflict`) and return `[R0, R1_A]`.
   * Approver 2's vault reports that Approver 1 approved `R0`, keeps Approver 2's edits, and asks Approver 2 to sign against `H1_A` under a new challenge (Section 4.4).
   * The result, `R0 -> R1_A (APPROVE H0) -> R2 (SUPERCEDE H1_A)`, records that Approver 1 approved `R0` and Approver 2 then replaced the parameters. Approver 1's approval no longer counts toward the quorum for the new parameters (Section 6, step 4).

## Atomicity and Durability of Chain State

The `head_node_hash`, terminal state, and consumed-challenge record of an intent are one unit. The RS MUST perform the CAS, the consumption of the appended node's `challenge_id` (and any attestation identifiers such as a PSEA `jti`), and the terminal transition as one atomic operation. Done separately, a crash between them can leave a consumed challenge without an advanced head, or an advanced head whose challenge can be presented again.

This state follows {{POI-CORE}} Section 7.1, step 5: it MUST survive restarts, MUST be shared by every instance that accepts envelopes for the intent, and when it is unavailable envelopes MUST be rejected.


# Extended Multi-Node Verification Algorithm

To verify a chained PoIE (`chain[0 ... n]`, `n >= 1`), a verifier MUST:

1. **Bound the chain:** Before any cryptography, check `2 <= length(chain) <= MAX_CHAIN_LENGTH` (RECOMMENDED default `16`). Otherwise fail with `400` (`malformed_poi_envelope`).
2. **Verify `R0`:** Run {{POI-CORE}} Section 7.1 step 1 on `chain[0].challenge_jws`, including the issuer check, and confirm `chain[0].node_hash == H0`.
3. **Verify each node `i = 1 ... n`:**
   * `chain[i].seq == i`.
   * The parent reference (`target_node_hash` or `supercedes_node_hash`) equals `chain[i-1].node_hash`.
   * The Node Challenge is `chain[i].challenge_jws` if present; otherwise the root challenge, allowed only for `i == 1`. Verify a carried challenge as in {{POI-CORE}} Section 7.1 step 1 at the time it was answered (at ingestion, now), check that its `intent_id` equals the root's, and check that its `prior_chain` matches `chain[0 ... i-1]` (Section 4.4).
   * A `REJECT` at `i < n` fails with `chain_continuity_broken`: a `REJECT` node is terminal and MUST NOT have child nodes.
   * For `SUPERCEDE`, `SHA-256(JCS(asserted_params))` over the parsed JSON equals `asserted_params_hash`.
   * Verify the attestation as in {{POI-CORE}} Section 7.1 step 3, using the Node Challenge in place of the root challenge: audience, intent and challenge binding, decision, and tier from evidence. For `APPROVE`, the committed parameters are those in effect at the parent (the nearest preceding `asserted_params`, or `R0.raw_params`).
   * `chain[i].node_hash` equals the hash computed per {{POI-CORE}} Section 6.1.
4. **Effective parameters and signers:**
   * Let `k_last_supercede` be the largest `k` (`1 <= k <= n`) with `chain[k].node_type == "SUPERCEDE"`, or `0` if none.
   * The effective parameters are `chain[k_last_supercede].asserted_params`, or `R0.raw_params` when `k_last_supercede == 0`.
   * **Quorum:** An `APPROVE` at `j < k_last_supercede` approved parameters that were later replaced. Policy MUST count only signers at `i >= k_last_supercede` toward quorum or escalation authority.
5. **Admit the appended node (RS only):** Apply the CAS (Section 5.1) and consume the node's challenge and attestation identifiers in one atomic operation (Section 5.5). Auditors run steps 1 to 4 only.


# Chained State and Concurrency Error Modes

## Escalation and Concurrency Error Definitions

In addition to the 20 error codes in Section 8 of {{POI-CORE}}, this extension defines four:

* **`authority_escalation_required`** (`202` or `403`): A verified `SUPERCEDE` (`Rk`) exceeds the signer's limit (Section 4.2, outcome 3). For asynchronous escalation the RS SHOULD return `202` with `"poi_status": "pending_escalation"`; for synchronous multi-party approval it MUST return `403` with `PoI-Challenge: error="authority_escalation_required"`.
* **`stale_head_conflict`** (`409`): A node at `seq: k + 1` failed the CAS because another signer already moved `head_node_hash` from `Hk` to `H_(k+1)` and the intent is still open (Section 5.1). The {{RFC9457}} body MUST include `current_head_node_hash` and the current `chain` (`[R0, ..., R_(k+1)]`) so the vault can show the new node and ask the signer to sign against `H_(k+1)`.
* **`intent_already_finalized`** (`409`): The node arrived after another signer's `APPROVE`, `REJECT`, or authoritative `SUPERCEDE` made the intent terminal (CIR issued). The body SHOULD include that CIR.
* **`context_state_drifted`** (`409`): In asynchronous flows (Section 3), the domain record changed between the proposal or challenge (`context_state_hash`) and submission.

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

For asynchronous review, the RS MUST NOT mint long-lived challenges at proposal time (`t0`). It MUST bind `context_state_hash` in the challenge minted at review time (`t1`) and recheck it atomically when committing the terminal node.

## Lineage Integrity Across Escalation Hops

An intermediary could try to drop `R1` or alter the first signer's justification before the next approver (`R2`) sees it. Each `Hk` covers the whole node, including its attestation, decision, parent hash, and any carried challenge ({{POI-CORE}} Section 6.1), and the escalation ICO signs `prior_chain: [R0, R1]`. Any change breaks both the hash chain and the RS signature.

Verifiers MUST NOT count `APPROVE` signatures at `j < k_last_supercede` toward quorum for parameters replaced at `k_last_supercede` (Section 6, step 4). Otherwise an approval of `R0` would count as approval of the replacement.

## Replay of Escalation and Step-Up Approvals

Each append answers its own challenge (Section 4.4), consumed atomically with the CAS (Section 5.5). A captured node cannot be replayed: its parent is no longer the head and its challenge is already consumed. Consuming challenges separately from the CAS, or holding either in process memory, reopens this replay after a crash or on another instance.

## Recovery Across Escalation

{{POI-CORE}} Section 9.4 applies to escrowed intents. Because `intent_id` is stable for the life of the intent, the RS MUST NOT admit another append while an earlier admission has an unknown outcome, so escalation or re-approval cannot reopen an action that may already have run.

## Denial-of-Service Mitigation via Bounded Chain Depth

Each node costs one or more signature verifications (for example, a KCT and an assertion at Tier 1) and, at Tier 2 and Tier 3, an enrollment lookup. Without a bound, a client could send thousands of nodes. Verifiers MUST enforce `MAX_CHAIN_LENGTH` (Section 6, step 1) before any signature check.


# IANA Considerations

## PoI Error Code Registrations

This document adds four codes to the "Proof-of-Intent (PoI) Error Codes" registry (`urn:ietf:params:oauth:poi:error`) from Section 11.3 of {{POI-CORE}}:

* `authority_escalation_required` (Section 7.1)
* `stale_head_conflict` (Section 7.1)
* `intent_already_finalized` (Section 7.1)
* `context_state_drifted` (Section 7.1)

## JWT Claim Registrations

This document registers in the "JSON Web Token Claims" registry ({{RFC7519}}):

* `context_state_hash`: Digest of the RS domain state when the challenge was issued (Section 3.2).
* `prior_chain`: Verified predecessor nodes in an escalation challenge (Section 4.3).
* `current_head_node_hash`: The current head `node_hash`, returned with `stale_head_conflict` (Section 7.1).


# Implementation Status

Note to RFC Editor: please remove this section and the reference to {{RFC7942}} before publication.

This section records known implementations of this extension at the time of posting, per {{RFC7942}}. Listing does not imply IETF endorsement.

* **Organization:** Barefoot Coders, LLC (Mandrel Project).
* **Implementation:** The Mandrel reference implementation described in {{POI-CORE}}, Implementation Status, tag `poi-core-01-rc.2`.
* **Coverage:** `mandrel-go` verifies chains of up to 16 nodes: sequence, parent links, each node's attestation against its Node Challenge, and carried challenges' `prior_chain` (Section 4.4). It treats any `REJECT` as terminal (`intent_rejected`) and tracks effective parameters across `SUPERCEDE` nodes. `mandrel-collet` implements quorum from a policy `min-approvals` count of distinct signers at or after the last `SUPERCEDE`: an unmet quorum records the chain as pending and issues an escalation challenge with `prior_chain`, and appends are admitted through the CAS, atomically with challenge consumption, in a shared durable store. It returns `stale_head_conflict`, `authority_escalation_required`, and `intent_already_finalized`.
* **Known gaps:** Reviewer-queue escrow, minting challenges on request, and `context_state_hash` are not implemented; they need an RS that owns the domain records, which a gateway sidecar does not. Escalation on per-signer authority limits (Section 4.2, outcome 3) and `context_state_drifted` are not implemented; quorum uses the policy approval count only.
* **Maturity:** Prototype.
* **Contact:** Paul Charles Williams (paul@barefootcoders.com).
