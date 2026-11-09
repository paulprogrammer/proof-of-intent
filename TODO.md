# Proof-of-Intent (PoI) Work Tracker

Status key: `[x]` done and verified, `[ ]` open. Items marked **(reopened)** were previously checked off; the 2026-11-09 adversarial review found the claim overstated. The note under each one says what is missing.

---

## 1. Specification Track (`draft-williams-oauth-poi-core-01`)

### 1.1 Completed

- [x] **Initialize -01 Draft**: Cloned source, updated document header, and verified with `idnits`.
- [x] **Pre-Commit Historical Draft Locking**: Enforced immutable historical draft rules via `.githooks/pre-commit`.
- [x] **SUPERCEDE Parameter Replacement (Section 6.2 & 9.5)**:
  - [x] Codified the full replacement invariant (omitted parameters from `R0` must not survive into executable input).
- [x] **PSEA Header and Media Type Distinction**: Section 6.3.3.2 and Section 7.1 document `application/psea+jwt` (media type) vs. protected header `typ: "psea-proof+jwt"`.

### 1.2 Reopened

- [ ] **Attestation Profile Conformance (Section 6.3)** (reopened)
  - [x] Formulated the 5 abstract attestation preconditions.
  - [ ] Add decision binding to the preconditions. Precondition 1 and the precondition 5 extraction tuple omit `decision`, so an attestation can be valid without committing to APPROVE vs. REJECT vs. SUPERCEDE. This is the spec-level root of the WebAuthn relabel bug (Section 2.2).
  - [ ] Correct the PSEA applicability assessment (6.3.3.2). As profiled, PSEA binds neither `target_node_hash` nor `intent_id`, so it fails preconditions 2 and 3 under the draft's own MUST-reject rule. Rewrite as "compliant when profiled as follows": require `eat_nonce` = the parent node hash (or an intent/challenge digest), `psea_stepup_selection` carrying the decision, and mandatory appraisal of `aud`, `psea_op` and `psea_tier`.
  - [ ] Define the mapping from `psea_tier` to PoI Tier 2 and Tier 3. PSEA does not distinguish platform from roaming authenticators, so the Tier 3 claim needs a basis or should be dropped.
  - [ ] Resolve the WebAuthn challenge contradiction. 6.3.3.3 (line ~392) says the Resource Server computes the challenge hash; 7.1 step 3 (line ~422) says `SHA-256(JCS(assertion_payload))`. Only the second can cover the decision and SUPERCEDE parameters. Keep 7.1.
  - [ ] State that Direct WebAuthn needs Resource Server enrollment state (credential ID to `sub` and credential class), which conflicts with "statelessly" in precondition 5.
- [ ] **Application Crash Recovery Demarcation (Section 9.4)** (reopened)
  - Note: Does not answer a reviewer's actual question. `head_node_hash` changes on reapproval, and nothing requires `intent_id` to survive a fresh challenge.
  - [ ] Require that a fresh challenge for the same business occurrence reuse the same `intent_id`.
  - [ ] State that retries happen after admission and are keyed on the CIR; re-presenting a consumed PoIE is a 409 by design, which contradicts the current "replays ... without user intervention" wording.
  - [ ] Remove or soften the MUST placed on downstream providers; it is outside protocol authority.
- [ ] **PSEA Temporal Lifetime** (reopened)
  - Note: 6.3.3.2 states a strict `iat <= t_eval <= exp`, while the verifier allows 60 s of clock skew. Pick one and make the code and text match.
- [ ] **Informative Citations Polish** (reopened)
  - Note: The `PSEA` reference entry (lines ~70-73) is wrong against Datatracker.
  - [ ] Title: "PSEA Token Profile: An EAT Profile for Action-Bound, User-Verification-Gated Transaction-Confirmation Evidence".
  - [ ] Organization: Yuthent (currently "Yuthentic").
  - [ ] Date: 2026-10-08 for -03 (currently 2026-02).
  - [x] `EP-RECEIPTS` entry verified: title, author, organization and -13 revision match Datatracker.

### 1.3 New Items from the 2026-11-09 Review

- [ ] **Stateless vs. Stateful Framing**: The abstract, Section 1.2 and the Section 7 title say "stateless" while 7.1 requires a consumed-challenge check. Reframe as stateless evidence verification plus stateful admission.
- [ ] **Consumed-State Requirements (Section 7.1)**: Require consumed state to be durable across restart, shared across replicas, and retained for at least `exp + ClockSkewTolerance`.
- [ ] **Replay Key Consistency**: The draft consumes `challenge_id`; the code consumes `intent_id`. Decide which, and say why.
- [ ] **CIR Alignment Claim (Section 7.2 item 4, line ~437)**: Drop "structural semantics ... align with" EP receipts, or scope it to "can be mapped to". Label matching is insufficient, and EP separates pre-execution approval evidence from terminal consumption evidence. The CIR is minted before forwarding.
- [ ] **Wire Format Drift**: The `attestation: {format, token}` container (6.3.1, 7.1 step 3) is not implemented; the code still uses `assertion_jws` / `webauthn_proof`. Either update the code or document the legacy fields.
- [ ] **IANA Registry Citation (line ~641)**: "Specification Required" cites RFC 8174; it should cite RFC 8126.
- [ ] **`application/webauthn+json`**: Not a registered media type. Register it in Section 11.1 or switch to a URI identifier.
- [ ] **`display_facts` Serialization**: Three permitted shapes (string, array, map) undermine deterministic rendering. Consider narrowing to one.
- [ ] **Chained State Draft Refresh**: `draft-williams-oauth-poi-chained-state-00` still references core -00 and the pre-container node fields. Cut a -01 aligned with core -01.

---

## 2. Reference Implementation Track (`mandrel-collet` and `mandrel-go` on `feat/poi-reference-impl`)

### 2.1 Completed

- [x] **Submodule Setup**: Added `mandrel-collet` and `mandrel-go` submodules via native SSH.
- [x] **Working Branches**: Created and checked out `feat/poi-reference-impl` in both submodules.
- [x] **Bug Fix: `CommittedParamsHash` Assignment**: `layers.go` computes `poi.HashParams(result.EffectiveParams)`. Note: correct but currently unobservable outside tests (see Receipt Propagation below).
- [x] **Bug Fix: Complete Parameter Replacement on `SUPERCEDE`**: `req.Context` is replaced wholesale. Follow-up tracked under Metadata Separation.

### 2.2 Critical: Fix Before Any Collaborator Review

- [ ] **Override Token Bypass**: `mandrel-collet/pkg/enforcement/layers.go:460` skips PoI for `challenge` actions when `mandrel.override_token` or `override_token` is any non-empty string. Nothing validates the token, although the log says "valid Override Token". Present at 6488224 (the commit a reviewer reviewed). Validate a signed, scoped, expiring token or remove the path.
- [ ] **WebAuthn Decision Not Signed**: `mandrel-go/pkg/poi/verifier.go:344` uses `SHA-256(prevNode.NodeHash)` as the challenge, so a REJECT signature relabeled as APPROVE verifies (PoC confirmed). Bind the challenge to `SHA-256(JCS(assertion_payload))` per draft 7.1.
- [ ] **WebAuthn Relying Party Checks**: `webauthn.go` does not verify `origin`, `crossOrigin`/`topOrigin`, the RP ID hash (`authenticatorData[0:32]`), sign count, or credential class. PoC passed with an attacker origin and a zero RP ID hash.
- [ ] **PSEA Binding and Appraisal**: `VerifyPSEAToken` checks only the signature, `typ`, time and `psea_uv`. A token with the wrong `aud` and a reused `jti` approved two distinct intents (PoC confirmed). Require `eat_nonce` bound to the chain, appraise `aud`, `iss`, `psea_op` and `psea_tier` inside the verifier, require `exp`, and consume `jti`.
- [ ] **Enrolled Key Fallback to IdP Key**: `verifier.go:278` and `verifier.go:337` fall back to `idpPubKey` when the `kid` or credential ID does not resolve. An IdP-signed PSEA token with no `exp` verified at hardware tier (PoC confirmed). Collet never passes `WithKeyResolver`, so this fallback is its only path, and with no IdP configured it uses Collet's own key. Fail closed on resolution miss and wire a resolver into Collet.
- [ ] **Self-Declared Assurance Tier**: `node.AssuranceTier` is client-supplied. Collet's tier check at `layers.go:562` treats `webauthn-hw` as satisfying any requirement. Derive the tier from enrollment and attestation evidence, never from the node label.

### 2.3 Reopened

- [ ] **Feature: Stateful Consume-Once Check** (reopened)
  - [x] Wrapped `VerifyEnvelope` with `TryConsume` on a namespaced in-memory tracker.
  - [ ] Close the clock-skew replay window: tracker entries expire at `ico.Exp`, the verifier accepts until `ico.Exp + 60s`, and `TryConsume` overwrites expired entries. Retain until `exp + ClockSkewTolerance`.
  - [ ] Provide a durable, shared tracker (e.g. Redis or SQL) and fail closed when none is configured outside dev mode. The in-memory store re-opens every consumed intent on restart or on a second replica.
  - [ ] Fix `intent_id` minting (`intent-<turn>-<unix seconds>`): two challenges in one turn within one second collide and produce false `challenge_replayed` rejections. Use a random ID or key on `challenge_id`.
  - [ ] Evaluate cross-namespace replay: trackers are per spec name, and the challenge `iss` is not checked against the enforcing spec.
- [ ] **Feature: PSEA Attestation Verifier Integration** (reopened)
  - [x] Unpacker for `typ: "psea-proof+jwt"` with signature, time and UV checks.
  - [ ] Binding and appraisal gaps: see Critical section.
  - [ ] SUPERCEDE at PSEA and WebAuthn tiers never updates effective parameters (`verifier.go:292`); a SUPERCEDE silently approves `R0` (PoC confirmed). Carry asserted parameters in the signed input or reject SUPERCEDE at these tiers.
  - [ ] Type-preserving parameters: `map[string]string` cannot reproduce the PSEA -03 baseline sample (numeric `amount: 500`). Hashes confirmed to differ. Move to typed JSON values end to end.
- [ ] **Feature: Passkey / WebAuthn Verification** (reopened)
  - [x] Replaced the `unsupported assurance tier` stub with signature and UP/UV verification.
  - [ ] Decision binding and relying party checks: see Critical section.
- [ ] **Regression & Conformance Test Suite** (reopened)
  - [x] SUPERCEDE parameter omission, CIR hash, in-flight tampering, replay (sequential, concurrent, TTL, namespaced).
  - [ ] Port the review PoCs as negative tests: WebAuthn REJECT relabel, PSEA cross-intent reuse, IdP-key fallback, PSEA SUPERCEDE keeping `R0`, vector type mismatch. Temporary copies live in the review session scratchpad and will not persist.
  - [ ] Review regression cases: restart between admission and completion, provider success with failed completion recording, wrong origin/RP ID/challenge on the real WebAuthn path, and explicit expected-tier enforcement.
  - [ ] Replay inside the skew window (`ico.Exp < t <= ico.Exp + 60s`).
  - [ ] Override token with an arbitrary value must not bypass PoI.

### 2.4 New Items from the 2026-11-09 Review

- [ ] **Release Plumbing**: The Collet Dockerfile builds with `GOWORK=off`, and `mandrel-collet/go.mod` pins mandrel-go v1.0.17, so the shipped image lacks the PSEA and WebAuthn code. Tag mandrel-go, bump the pin, and confirm the image build.
- [ ] **Receipt Propagation**: The CIR is stored in a Go `context.Value`, which gRPC does not transmit. Attach it to outgoing metadata and/or the response so the target and caller can see it.
- [ ] **Receipt Semantics**: The CIR is minted before forwarding. Either document it as admission evidence only, or add a separate completion record after the target responds.
- [ ] **Metadata Separation on SUPERCEDE**: Wholesale replacement drops non-executable keys (trace, tenant, routing). Split executable parameters from metadata, replace only the former, then compare exactly before forwarding.
- [ ] **Unknown-Outcome Handling**: A target error after consumption burns the intent with no record beyond telemetry. Record the consumed/unknown state for reconciliation.
- [ ] **Signature Malleability**: The DER parser ignores trailing bytes, and raw vs. DER re-encoding changes the node hash without invalidating the signature. Use strict parsing.

---

## 3. Test Vectors & Interoperability

- [x] **Test Vector Organization**: `psea-03-baseline-sample.json` lives in `testdata/vectors/psea/`.
- [x] **Reference Verifier Test**: `mandrel-go/pkg/poi/psea_test.go` verifies the baseline token. Note: standalone only. The `iss`/`aud`/`op` checks happen in the test body, and the vector cannot pass through `VerifyEnvelope` until typed parameters land.
- [ ] **Baseline Vector Through the Envelope Path**: Verify the PSEA baseline token inside a full PoIE once typed parameters and the binding profile are in place.
- [ ] **Upstream Conformance Vectors**: Mirror the 31 negative/positive conformance vectors from `psea-spec` into `testdata/vectors/psea/conformance/`.

---


## 5. Activity Log

Newest first. Record what was done, what was found, and what was decided.

### 2026-11-09

- **Adversarial review of draft -01 and both submodules** against OAuth WG review feedback (OAuth WG review feedback and the PSEA -03 baseline sample).
  - Scope: diffs since Collet 6488224 and mandrel-go 7ac18ba; the full `enforcePoIChallenge` path, `server.go` forwarding, the PSEA and WebAuthn verifier branches, and the -00 to -01 draft diff.
  - Ran `go test` in both submodules: all pass. `GOWORK=off go build` of Collet succeeds against v1.0.17, which revealed the release plumbing gap.
  - Wrote throwaway PoC tests against local mandrel-go. Confirmed WebAuthn decision relabel, PSEA cross-intent reuse, IdP-key fallback with no `exp`, PSEA SUPERCEDE keeping `R0`, and the parameter type mismatch.
  - Verified on Datatracker: the EP-RECEIPTS citation is correct; the PSEA citation has the wrong title, organization and date.
  - Outcome: reopened 7 previously checked items and added the new items above. Collaborator replies are gated on fixes.
- **Process decision**: commits in this repo and its submodules carry no Claude co-author or attribution trailer.
- **Prior work recorded in git** (`226a7da` .. `0515c1d`): P1/P2 Collet fixes, P3 consume-once tracker, namespaced tracker registry, P4 PSEA and WebAuthn verifier integration.
