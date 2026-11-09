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
- [x] **Additional Submodules (2026-11-09)**: Added `mandrel-demo` (mock Signing Vault and demo harness) and `mandrel-spec` (proto, schema, vectors) on new local `feat/poi-reference-impl` branches; `mandrel-demo` added to `go.work`. Rule recorded in `CONTRIBUTING.md` Section 3: PoI feature work is edited only in the submodules, never on submodule `main`.
  - [ ] Push the `feat/poi-reference-impl` branches for `mandrel-demo` and `mandrel-spec` when they first carry changes (currently local only).
  - [x] Fix `scripts/demo-poi.sh` so it gates: per-scenario assertions with non-zero exit, space-delimited scope token, readiness waits, pinned image, optional `BUILD=1`, no repo relabeling. Passes 6/6 against tier 0 code; fails 5/6 against a weakened spec (uncommitted).
  - [x] Demo uses signed access tokens: Mock IdP `IssueAccessToken`, orchestrator mints a token from `--token` scopes when `--idp-key` is set (`--token-aud`), demo Collet runs with the user-token flags, and scenarios 7 and 8 reject an unsigned scope string and an `alg=none` JWT. README walkthrough updated (it referenced a nonexistent `--hitl-token` flag) and verified by hand.
  - [ ] Update the mock Signing Vault for `assertion_payload` (WebAuthn) and the PSEA nonce/selection profile, and add tier 2 / tier 3 demo scenarios.
  - [x] PSEA sample moved into mandrel-go (`pkg/poi/testdata/interop/psea/`), not mandrel-spec: the sender says it is not a conformance vector, and mandrel-spec `docs/metrology/conformance.md` requires Core implementations to pass every vector under `vectors/`. Revisit mandrel-spec when PoI has normative vectors (scope the conformance doc and add a `validate-vectors` family first).
- [x] **Bug Fix: `CommittedParamsHash` Assignment**: `layers.go` computes `poi.HashParams(result.EffectiveParams)`. Note: correct but currently unobservable outside tests (see Receipt Propagation below).
- [x] **Bug Fix: Complete Parameter Replacement on `SUPERCEDE`**: `req.Context` is replaced wholesale. Follow-up tracked under Metadata Separation.

### 2.2 Critical: Fix Before Any Collaborator Review (Tier 0, fixed 2026-11-09, uncommitted)

- [x] **Override Token Bypass**: Removed. `challenge` now fails closed like `challenge-always` and logs a warning when an override key is present. `TestEnforce_PoIActionRefinement` now asserts no bypass for either key.
  - [ ] Follow-up: specify a signed, scoped, expiring override format in mandrel-spec if `challenge` vs. `challenge-always` is still wanted.
- [x] **WebAuthn Decision Not Signed**: Nodes now carry `assertion_payload`; the WebAuthn challenge is `base64url(SHA-256(JCS(assertion_payload)))` per draft 7.1, and the payload must match aud, challenge_id, intent_id, seq, decision and parent hash. Relabel tests added.
- [x] **WebAuthn Relying Party Checks**: Origin allowlist, `crossOrigin`/`topOrigin` allowlist, RP ID hash and UV are always enforced; verification fails closed without a configured relying party. The sign count is returned and Collet requires it to increase (zero allowed for counterless authenticators).
  - [ ] Credential class (platform vs. cross-platform) is taken from the enrollment record's tier; registration-time attestation remains the enrollment system's job.
- [x] **PSEA Binding and Appraisal**: `eat_nonce` must equal base64url of the parent node digest, `psea_stepup_selection` must commit to `{decision, target_node_hash}`, and `iss`, `aud`, `psea_op`, `psea_tier`, `jti`, `iat` and `exp` are required and appraised in the verifier (`AppraisePSEA`). Collet consumes `(iss, jti)` once and requires `psea_counter` to strictly increase.
  - [ ] Confirm the nonce and selection construction with the PSEA author (PoI-side profile choice; PSEA leaves both deployment-defined).
- [x] **Enrolled Key Fallback to IdP Key**: Removed. Credentials resolve only through `WithCredentialResolver` / `WithEnrolledCredential`, with a profile check. Collet loads them from the new `--poi-trust-store` JSON file. Collet no longer substitutes its own key when no IdP key is configured; session-pop fails closed instead.
- [x] **Self-Declared Assurance Tier**: Node tier claims must be backed by the enrollment record (`TierSatisfies`). Collet checks the head signer's tier by rank; unknown required tiers fail closed. The undocumented `TierPSEA` URN was removed.

### 2.2a Follow-ups Created by the Tier 0 Fixes

- [ ] **Standalone Build Broken Until Release**: `GOWORK=off go build` of Collet now fails to compile against the pinned mandrel-go v1.0.17. This is louder than before (it previously built and shipped the old verifier). Resolved by Release Plumbing in 2.4.
- [ ] **Document `--poi-trust-store`**: Add the flag and file format to `content/docs/reference/collet.md` in mandrel-web, or the `flag-drift` CI check fails.
- [ ] **Draft: Document `assertion_payload`** on Direct WebAuthn nodes (6.3.3.3) and the PSEA nonce/selection profile (6.3.3.2).
- [ ] **Tier 1 Lineage Now Enforced**: Session-pop assertions must now match `seq` and `target_node_hash`/`supercedes_node_hash`, and REJECT must carry `decision: REJECT`. This is draft-conformant, but check mandrel-demo and Signing Vault clients for compatibility.
- [ ] **Counter Store Durability**: `MemoryCounterTracker` has the same restart and replica limits as the replay tracker; include it in the durable store work.

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
  - [x] SUPERCEDE at PSEA tier is now rejected (the token cannot carry asserted parameters). SUPERCEDE at WebAuthn tier works through the signed `assertion_payload`, and omitted `R0` keys are dropped (tested).
  - [ ] Type-preserving parameters: `map[string]string` cannot reproduce the PSEA -03 baseline sample (numeric `amount: 500`). Hashes confirmed to differ. Move to typed JSON values end to end.
- [ ] **Feature: Passkey / WebAuthn Verification** (reopened)
  - [x] Replaced the `unsupported assurance tier` stub with signature and UP/UV verification.
  - [x] Decision binding and relying party checks: see Critical section.
  - [ ] Interop test with a real authenticator ceremony (current tests use synthetic authenticator data).
- [ ] **Regression & Conformance Test Suite** (reopened)
  - [x] SUPERCEDE parameter omission, CIR hash, in-flight tampering, replay (sequential, concurrent, TTL, namespaced).
  - [x] Ported the review PoCs as negative tests in `mandrel-go/pkg/poi/webauthn_test.go` and `psea_envelope_test.go`: WebAuthn REJECT relabel, PSEA cross-intent reuse, IdP-key fallback, PSEA SUPERCEDE.
  - [ ] Vector type mismatch test (lands with typed parameters).
  - [ ] Review regression cases: restart between admission and completion, provider success with failed completion recording, wrong origin/RP ID/challenge on the real WebAuthn path, and explicit expected-tier enforcement.
  - [ ] Replay inside the skew window (`ico.Exp < t <= ico.Exp + 60s`).
  - [x] Override token with an arbitrary value must not bypass PoI.

### 2.4 New Items from the 2026-11-09 Review

- [x] **Unsigned Scope Tokens** (fixed 2026-11-09, uncommitted): Collet now verifies the user-delegated token (`usertoken.go`): ES256 signature under `--user-token-pubkey`, exact `--user-token-issuer`, `aud` containing `--user-token-audience`, required `exp`, optional `nbf`. Scopes come only from signed `scope`/`scp` claims; raw scope strings and `alg=none` JWTs are rejected with `Unauthenticated`. Collet refuses to start when the spec sets `required-oidc-scopes` without a verifier. mandrel-go `VerifyJWS` now rejects a nil key instead of panicking.
  - [ ] Decide scope semantics: `checkScopes` is any-of, while "required-oidc-scopes" reads as all-of. Spec decision for mandrel-spec.
  - [ ] JWKS and RS256 support with key rotation (only a single ES256 PEM key today).
  - [ ] Validate the RFC 8693 `act` claim the spec says the exchanged token carries.
  - [ ] Document `--user-token-pubkey`, `--user-token-issuer`, `--user-token-audience` in mandrel-web (flag-drift CI).
- [ ] **`enforce-dpop` Not Implemented**: The spec field defaults to `true` and mandrel-spec docs present it as a control, but Collet has no DPoP code. Implement or mark it unimplemented in the spec docs.

- [ ] **Release Plumbing**: The Collet Dockerfile builds with `GOWORK=off`, and `mandrel-collet/go.mod` pins mandrel-go v1.0.17, so the shipped image lacks the PSEA and WebAuthn code. Tag mandrel-go, bump the pin, and confirm the image build.
- [ ] **Receipt Propagation**: The CIR is stored in a Go `context.Value`, which gRPC does not transmit. Attach it to outgoing metadata and/or the response so the target and caller can see it.
- [ ] **Receipt Semantics**: The CIR is minted before forwarding. Either document it as admission evidence only, or add a separate completion record after the target responds.
- [ ] **Metadata Separation on SUPERCEDE**: Wholesale replacement drops non-executable keys (trace, tenant, routing). Split executable parameters from metadata, replace only the former, then compare exactly before forwarding.
- [ ] **Unknown-Outcome Handling**: A target error after consumption burns the intent with no record beyond telemetry. Record the consumed/unknown state for reconciliation.
- [ ] **Signature Malleability**: The DER parser ignores trailing bytes, and raw vs. DER re-encoding changes the node hash without invalidating the signature. Use strict parsing.

---

## 3. Test Vectors & Interoperability

- [x] **Test Vector Organization**: `psea-03-baseline-sample.json` lives in `mandrel-go/pkg/poi/testdata/interop/psea/` with a provenance README (moved from the parent repo's `testdata/` on 2026-11-09; byte-identical to the email attachment).
- [x] **Reference Verifier Test**: `mandrel-go/pkg/poi/psea_test.go` verifies the baseline token. Note: standalone only. The `iss`/`aud`/`op` checks happen in the test body, and the vector cannot pass through `VerifyEnvelope` until typed parameters land.
- [ ] **Baseline Vector Through the Envelope Path**: Verify the PSEA baseline token inside a full PoIE once typed parameters and the binding profile are in place.
- [x] **Vector Path Escapes mandrel-go**: `psea_test.go` now reads `testdata/interop/psea/` inside mandrel-go. Verified with a standalone copy of mandrel-go (`GOWORK=off go test ./...` passes) and `sync-vectors.sh --check` unaffected.
- [ ] **Upstream Conformance Vectors**: Mirror the 31 negative/positive conformance vectors from `psea-spec` into `mandrel-go/pkg/poi/testdata/interop/psea/conformance/` with the upstream commit recorded (previously planned for the parent repo `testdata/`).

---


## 5. Activity Log

Newest first. Record what was done, what was found, and what was decided.

### 2026-11-09

- **Migrated the PSEA sample into mandrel-go (uncommitted).** Moved `testdata/vectors/psea/psea-03-baseline-sample.json` from the parent repo to `mandrel-go/pkg/poi/testdata/interop/psea/` with a provenance README, repointed `psea_test.go`, and removed the parent `testdata/`. Decision: not mandrel-spec, because the sample is explicitly non-conformance and spec `vectors/` is a normative Core contract for metrology labs.
- **Committed submodule work on `feat/poi-reference-impl` (not pushed).** mandrel-go: `5e6655e` tier 2/3 binding, `4b7ddac` VerifyJWS nil key. mandrel-collet: `b48b555` override bypass removal, `b4a9843` tier 2/3 trust, `eb30c26` user token verification. mandrel-demo: `be45110` demo gate, `f8f865d` signed user tokens. Shared files were split by building intermediate versions into the index; each intermediate commit was built and tested in isolation.
- **Fixed the Collet scope check (uncommitted).** Replaced unverified claim parsing and raw-word matching with signed token verification and fail-closed startup. Collet tests (`go test -race`) pass, including 10 forgery cases and a startup configuration test; the demo gate passes 8/8 with two new forged-token scenarios. Found while tracing: `enforce-dpop` is declared but not implemented.
- **Fixed `mandrel-demo/scripts/demo-poi.sh` (uncommitted).** The committed script never passed a token; the orchestrator default was comma-separated while Collet parses space-delimited scopes, so all six scenarios failed at the scope layer while the script printed success (`|| true`). The script now asserts each outcome and exits non-zero on deviation; orchestrator default token fixed; README documents usage. Verified: 6/6 pass on tier 0 code; a spec with the threshold raised to $1000 fails 5/6 and exits 1.
- **Added `mandrel-demo` and `mandrel-spec` submodules.** mandrel-demo vets and builds against the tier 0 mandrel-go through `go.work`; it has no unit tests and the end-to-end demo script was not run. Decision: PoI feature work is edited only in the submodules; standalone clones under the Mandrel project directory stay on `main`.
- **Tier 0 fixes implemented (uncommitted)** in `mandrel-go` and `mandrel-collet` on `feat/poi-reference-impl`.
  - mandrel-go: new `attestations.go` (per-profile node verifiers and a shared signed-claims check), `tiers.go` (`TierRank`, `TierSatisfies`), `CredentialResolver`/`EnrolledCredential` replacing `KeyResolver`, `WebAuthnRelyingParty`, `AppraisePSEA`, `PSEANonceForParent`, `PSEASelectionCommitment`, `Node.AssertionPayload`, and new `VerifiedSigner` attestation fields. `VerifyWebAuthnProof` signature changed (unreleased API, introduced after v1.0.19).
  - mandrel-collet: override bypass removed, IdP self-key fallback removed, head-signer tier check, PSEA jti consumption and counter checks (`counters.go`), trust store loader (`truststore.go`), `--poi-trust-store` flag.
  - Tests: `go test -race` passes in both modules. mandrel-go has 21 new top-level tests (35 cases with subtests) replacing the two prior envelope tests; Collet has 7 new tests. Each negative case asserts its error code or denial reason.
  - Decision: override tokens fail closed because no format is specified anywhere; the old test asserted the bypass as a feature.
  - Decision: PSEA nonce = base64url(parent node digest); selection = base64url(SHA-256(JCS({decision, target_node_hash}))). Pending confirmation with the PSEA author.
- **Adversarial review of draft -01 and both submodules** against OAuth WG review feedback (OAuth WG review feedback and the PSEA -03 baseline sample).
  - Scope: diffs since Collet 6488224 and mandrel-go 7ac18ba; the full `enforcePoIChallenge` path, `server.go` forwarding, the PSEA and WebAuthn verifier branches, and the -00 to -01 draft diff.
  - Ran `go test` in both submodules: all pass. `GOWORK=off go build` of Collet succeeds against v1.0.17, which revealed the release plumbing gap.
  - Wrote throwaway PoC tests against local mandrel-go. Confirmed WebAuthn decision relabel, PSEA cross-intent reuse, IdP-key fallback with no `exp`, PSEA SUPERCEDE keeping `R0`, and the parameter type mismatch.
  - Verified on Datatracker: the EP-RECEIPTS citation is correct; the PSEA citation has the wrong title, organization and date.
  - Outcome: reopened 7 previously checked items and added the new items above. Collaborator replies are gated on fixes.
- **Process decision**: commits in this repo and its submodules carry no Claude co-author or attribution trailer.
- **Prior work recorded in git** (`226a7da` .. `0515c1d`): P1/P2 Collet fixes, P3 consume-once tracker, namespaced tracker registry, P4 PSEA and WebAuthn verifier integration.
