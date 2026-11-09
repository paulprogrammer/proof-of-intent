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

### 1.2 Draft -01 Corrections (done 2026-11-09, uncommitted; idnits clean)

- [x] **Attestation Profile Conformance (Section 6.3)**: six preconditions (added Decision Commitment; Intent and Challenge Binding no longer accepts a validity window alone; extraction tuple includes decision and challenge_id); tier ordering and enrollment-derived tiers; PSEA rewritten as "compliant when profiled" (aud/iss/op/tier, `eat_nonce`, `psea_stepup_selection`, `jti`, counter, SUPERCEDE rejected, tier from enrollment); WebAuthn challenge computed by the Signing Vault from `assertion_payload`; enrollment state stated.
- [x] **Wire format**: kept the `attestation` container (Section 6.3.1) and made it precise; session-key format is `application/poi+jwt;kind=assert` (matches the `kind` table); WebAuthn format is the URN `urn:ietf:params:oauth:poi:attestation:webauthn` instead of the unregistered `application/webauthn+json`.
- [x] **Section 9.4**: stable `intent_id` across reapproval (Section 5.2), retries after admission keyed on `intent_id`/CIR, unknown outcomes block reapproval, downstream idempotency softened to SHOULD.
- [x] **PSEA temporal lifetime** aligned with the 60-second skew.
- [x] **Citations**: PSEA title, organization (Yuthent) and date (2026-10-08); EP-RECEIPTS date (2026-09-11); RFC 8126 and RFC 7942 added.
- [x] **Stateless framing**: abstract, Section 1.2 and Section 7 now distinguish stateless evidence verification from stateful admission.
- [x] **Consumed-state requirements**: Section 7.1 step 5 (atomic, durable, shared, retained to `exp` plus skew, fail closed) and new Section 9.6.
- [x] **Replay key**: `challenge_id`; Section 7.1 also enforces `ico.iss`.
- [x] **CIR**: defined as admission evidence; EP-RECEIPTS alignment sentence replaced with a mapping caveat.
- [x] **IANA**: Specification Required cites RFC 8126; registry entries corrected; attestation URN registered.
- [x] **`display_facts`**: one shape (`title` plus ordered `fields` of `label`/`value`), matching the implementation.
- [x] **Digest encoding**: `sha256:` plus lowercase hex; profile encodings compared on decoded digest; node hash encoding defined in Section 6.1.
- [x] **Implementation Status** section (RFC 7942) pointing at `poi-core-01-rc.1`, with known gaps and per-repository licenses (Collet is BSL 1.1).

### 1.3 Remaining Specification Work

- [x] **Chained State Draft Refresh** (2026-11-09, uncommitted): `draft-williams-oauth-poi-chained-state-01` references core -01; drops the "stateless" framing; inherits the attestation container, six preconditions, consume-once admission and Section 9.4; uses the container in the example; adds Section 4.4 (each appended node carries and binds its own escalation or step-up challenge), Section 5.5 (CAS, challenge consumption and terminal transition in one atomic, durable, shared operation), per-node challenge verification in Section 6, Security Considerations 8.3 and 8.4, and an Implementation Status section. Step-up for `SUPERCEDE` excludes PSEA. idnits: no warnings (one comment: no Datatracker stream yet, same as -00).
- [x] **Core 6.1 node hash** for `k >= 1` defined as `SHA-256(JCS(node))` without `node_hash` (previously undefined beyond `H0`, yet used by CIR `head_node_hash` and the CAS).
- [ ] **Publish**: push this repository and submit core -01 to Datatracker once the collaborators' review points are settled.

### 1.4 Code Follow-ups Required by Draft -01 (implemented 2026-11-09, uncommitted)

- [x] `attestation` container (`format`, `token`) in mandrel-go (`attestation_container.go`) and the demo vault; legacy node fields still accepted during transition; mixing both, unregistered formats, and format/tier disagreement are rejected.
- [x] Node hash over the canonical node object for container nodes, computed from the transmitted bytes so unmodeled members are covered (`ComputeNodeHashRaw`).
- [x] Per-node challenges (chained-state 4.4) with `prior_chain` checked against the chain prefix; result exposes the head challenge, chain, head parent, and last `SUPERCEDE`.
- [x] `intent_id` reuse per business occurrence (spec, turn, attribute, parameters); completion releases it.
- [x] Intent ledger (memory and Redis, Lua-atomic): challenge consumption, outcome check, and chain CAS in one operation; outcomes recorded after forwarding (definitive gRPC errors: FAILED; transport/server errors: UNKNOWN; crash: stays ADMITTED); unknown outcomes block new challenges and admissions (`intent_outcome_unknown`, added to core -01); `ResolveIntentOutcome` for reconciliation; completion records kept 30 days.
- [x] Quorum escalation in Collet using policy `min-approvals`: distinct signers at or after the last `SUPERCEDE`; pending chains get an escalation challenge with `prior_chain`; losing concurrent appends get `stale_head_conflict`.
- [x] `psea_payload_hash` compared on the decoded digest.
- [x] Demo vault refuses non-conforming `display_facts` (`ValidateDisplayFacts`); Collet emits display fields in sorted order.
- [x] Detached `R0` marked OPTIONAL for Resource Servers in core 6.1 (not implemented).
- [x] **Release:** mandrel-go `v1.1.0-rc.2` (`5fd2bac`) published; Collet pins it (`87f17c5`) and passes standalone build, race tests and `podman build`. All five feature branches pushed and tagged `poi-core-01-rc.2`.
- [ ] Enforce `editable_schema`: reject `SUPERCEDE` `asserted_params` outside the signed schema (core 5.2). The field was briefly marked deprecated in error; it is an unimplemented feature.
- [ ] Authenticated operator interface for resolving unknown outcomes (today a library call, `ResolveIntentOutcome`).
- [ ] Chained-state items that need a domain Resource Server rather than a gateway sidecar: reviewer queue escrow, just-in-time minting on request, `context_state_hash`, per-signer authority-limit escalation, `context_state_drifted`.

---

## 2. Reference Implementation Track (`mandrel-collet` and `mandrel-go` on `feat/poi-reference-impl`)

### 2.1 Completed

- [x] **Submodule Setup**: Added `mandrel-collet` and `mandrel-go` submodules via native SSH.
- [x] **Working Branches**: Created and checked out `feat/poi-reference-impl` in both submodules.
- [x] **Additional Submodules (2026-11-09)**: Added `mandrel-demo` (mock Signing Vault and demo harness) and `mandrel-spec` (proto, schema, vectors) on new local `feat/poi-reference-impl` branches; `mandrel-demo` added to `go.work`. Rule recorded in `CONTRIBUTING.md` Section 3: PoI feature work is edited only in the submodules, never on submodule `main`.
  - [ ] Push the `feat/poi-reference-impl` branches for `mandrel-demo` and `mandrel-spec` when they first carry changes (currently local only).
  - [x] mandrel-spec brought into the feature scope (2026-11-09): `scripts/verify-poi.sh` verifies all four submodules together (spec schema tests, mandrel-go race/standalone/vector drift, Collet, demo build, optional podman gate) and fails if any submodule is off `feat/poi-reference-impl`. `CONTRIBUTING.md` records the landing order and the mandrel-spec DCO rule.
  - [ ] Commit the mandrel-spec override-token changes on `feat/poi-reference-impl` with `git commit -s` (awaiting approval per mandrel-spec AGENTS.md), then pin the parent pointer.
  - [x] Fix `scripts/demo-poi.sh` so it gates: per-scenario assertions with non-zero exit, space-delimited scope token, readiness waits, pinned image, optional `BUILD=1`, no repo relabeling. Passes 6/6 against tier 0 code; fails 5/6 against a weakened spec (uncommitted).
  - [x] Demo uses signed access tokens: Mock IdP `IssueAccessToken`, orchestrator mints a token from `--token` scopes when `--idp-key` is set (`--token-aud`), demo Collet runs with the user-token flags, and scenarios 7 and 8 reject an unsigned scope string and an `alg=none` JWT. README walkthrough updated (it referenced a nonexistent `--hitl-token` flag) and verified by hand.
  - [ ] Update the mock Signing Vault for `assertion_payload` (WebAuthn) and the PSEA nonce/selection profile, and add tier 2 / tier 3 demo scenarios.
  - [x] PSEA sample moved into mandrel-go (`pkg/poi/testdata/interop/psea/`), not mandrel-spec: the sender says it is not a conformance vector, and mandrel-spec `docs/metrology/conformance.md` requires Core implementations to pass every vector under `vectors/`. Revisit mandrel-spec when PoI has normative vectors (scope the conformance doc and add a `validate-vectors` family first).
- [x] **Bug Fix: `CommittedParamsHash` Assignment**: `layers.go` computes `poi.HashParams(result.EffectiveParams)`. Note: correct but currently unobservable outside tests (see Receipt Propagation below).
- [x] **Bug Fix: Complete Parameter Replacement on `SUPERCEDE`**: `req.Context` is replaced wholesale. Follow-up tracked under Metadata Separation.

### 2.2 Critical: Fix Before Any Collaborator Review (Tier 0, fixed 2026-11-09, uncommitted)

- [x] **Override Token Bypass**: Removed. `challenge` now fails closed like `challenge-always` and logs a warning when an override key is present. `TestEnforce_PoIActionRefinement` now asserts no bypass for either key.
  - [x] Override token semantics decided 2026-11-09 (option 1, retire): mandrel-spec schema descriptions and `docs/identity.md` 2.3.4 define `challenge` as equivalent to `challenge-always` with no override token; draft -01 Section 9.1 states PoI defines no override, bypass, or standing-approval token; Collet comment updated (uncommitted). A receipt-bound retry may be revisited after the durable store (item 10) and completion records exist; standing grants stay out of PoI Core.
  - [x] `challenge-always` removed 2026-11-09 (uncommitted): mandrel-spec schema enums, descriptions, `identity.md` 2.3.4, `v1-core.md`, and a negative/positive fixture pair; mandrel-go `spec.ValidateActions` rejects removed or unknown actions in `LoadSpec` with a migration hint; Collet denies unknown actions at runtime (previously they fell through to allow). Breaking: specs using `challenge-always` fail validation and Collet refuses to load them; signed Realized Specs carrying it must be re-baked.
  - [x] mandrel-cli brought into the submodule scope (2026-11-09, uncommitted): the validator rejects `challenge-always` in all three fields with a migration hint (E004/E025/E030); the Rego generator emits a fail-closed deny rule for unknown actions (it previously treated them as autonomous) and escapes the action value; generated Rego compiled and evaluated with OPA 1.10.1. Standalone build against its v1.0.17 pin still works.
  - [ ] Still using `challenge-always` outside scope: mandrel-web (spec/identity.md, spec/core-schema.md, overview/roadmap.md, overview/workload-maturity.md) and mandrel-internal (two feature notes). Docs only.
  - [ ] mandrel-cli generator embeds `matrix.Attribute` and tier descriptions into Rego strings without escaping (pre-existing); escape them like the action value.
  - [ ] mandrel-spec `docs/identity.md` 2.3.1-2.3.2 still describe a `human_approval_token` JWT with `turn_id`; the implemented contract is `poi_envelope`. Rewrite that section around the PoIE.
- [x] **WebAuthn Decision Not Signed**: Nodes now carry `assertion_payload`; the WebAuthn challenge is `base64url(SHA-256(JCS(assertion_payload)))` per draft 7.1, and the payload must match aud, challenge_id, intent_id, seq, decision and parent hash. Relabel tests added.
- [x] **WebAuthn Relying Party Checks**: Origin allowlist, `crossOrigin`/`topOrigin` allowlist, RP ID hash and UV are always enforced; verification fails closed without a configured relying party. The sign count is returned and Collet requires it to increase (zero allowed for counterless authenticators).
  - [ ] Credential class (platform vs. cross-platform) is taken from the enrollment record's tier; registration-time attestation remains the enrollment system's job.
- [x] **PSEA Binding and Appraisal**: `eat_nonce` must equal base64url of the parent node digest, `psea_stepup_selection` must commit to `{decision, target_node_hash}`, and `iss`, `aud`, `psea_op`, `psea_tier`, `jti`, `iat` and `exp` are required and appraised in the verifier (`AppraisePSEA`). Collet consumes `(iss, jti)` once and requires `psea_counter` to strictly increase.
  - [ ] Confirm the nonce and selection construction with the PSEA author (PoI-side profile choice; PSEA leaves both deployment-defined).
- [x] **Enrolled Key Fallback to IdP Key**: Removed. Credentials resolve only through `WithCredentialResolver` / `WithEnrolledCredential`, with a profile check. Collet loads them from the new `--poi-trust-store` JSON file. Collet no longer substitutes its own key when no IdP key is configured; session-pop fails closed instead.
- [x] **Self-Declared Assurance Tier**: Node tier claims must be backed by the enrollment record (`TierSatisfies`). Collet checks the head signer's tier by rank; unknown required tiers fail closed. The undocumented `TierPSEA` URN was removed.

### 2.2a Follow-ups Created by the Tier 0 Fixes

- [ ] **Standalone Build Broken Until Release**: `GOWORK=off go build` of Collet now fails to compile against the pinned mandrel-go v1.0.17. This is louder than before (it previously built and shipped the old verifier). Resolved by Release Plumbing in 2.4.
- [ ] **Document new Collet flags in mandrel-web** (`content/docs/reference/collet.md`, or `flag-drift` CI fails): `--poi-trust-store` and its file format, `--user-token-pubkey`, `--user-token-issuer`, `--user-token-audience`, and `--replay-store`.
- [x] **Draft: Document `assertion_payload`** on Direct WebAuthn nodes (6.3.3.3) and the PSEA nonce/selection profile (6.3.3.2). Done in -01 corrections.
- [ ] **Tier 1 Lineage Now Enforced**: Session-pop assertions must now match `seq` and `target_node_hash`/`supercedes_node_hash`, and REJECT must carry `decision: REJECT`. This is draft-conformant, but check mandrel-demo and Signing Vault clients for compatibility.
- [x] **Counter Store Durability** (2026-11-09): `RedisStore.Advance` performs the compare-and-advance in a Lua script; semantics are tested identical to `MemoryCounterTracker`.

### 2.3 Reopened

- [ ] **Feature: Stateful Consume-Once Check** (reopened)
  - [x] Wrapped `VerifyEnvelope` with `TryConsume` on a namespaced in-memory tracker.
  - [x] Clock-skew replay window closed (2026-11-09): entries are retained until `exp + ClockSkewTolerance`, using the verified challenge `exp` (the unverified re-parse and its 5-minute default are gone). The mandrel-go verifier now requires `exp` and `challenge_id`. Regression test fails without the fix.
  - [x] Durable shared store (2026-11-09): `--replay-store redis://...` (SET NX with TTL for consumption, Lua compare-and-advance for counters). A spec that issues challenges refuses to start without an explicit `--replay-store`; `memory` is allowed with a warning; Redis errors fail closed (`Unavailable`). Tested with miniredis, including a simulated restart.
  - [x] Random 128-bit challenge and intent IDs (2026-11-09).
  - [x] Challenge issuer enforced (2026-11-09): `poi.WithChallengeIssuer` rejects challenges minted for another Collet issuer sharing the signing key.
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
  - [ ] Review regression cases: restart (Redis store test), unknown outcome after admission, and crash before outcome recording are covered.
  - [x] Replay inside the skew window (`TestReplay_InsideSkewWindow_Negative`).
  - [x] Override token with an arbitrary value must not bypass PoI.

### 2.4 New Items from the 2026-11-09 Review

- [x] **Unsigned Scope Tokens** (fixed 2026-11-09, uncommitted): Collet now verifies the user-delegated token (`usertoken.go`): ES256 signature under `--user-token-pubkey`, exact `--user-token-issuer`, `aud` containing `--user-token-audience`, required `exp`, optional `nbf`. Scopes come only from signed `scope`/`scp` claims; raw scope strings and `alg=none` JWTs are rejected with `Unauthenticated`. Collet refuses to start when the spec sets `required-oidc-scopes` without a verifier. mandrel-go `VerifyJWS` now rejects a nil key instead of panicking.
  - [x] **Decided 2026-11-09: all-of.** A token must carry every scope listed in `identity.required-oidc-scopes`. Change `checkScopes` and its tests, update the Collet error message, and state the semantics in mandrel-spec `docs/extensions.md`.
  - [ ] JWKS and RS256 support with key rotation (only a single ES256 PEM key today).
  - [ ] Validate the RFC 8693 `act` claim the spec says the exchanged token carries.
  - [ ] Document `--user-token-pubkey`, `--user-token-issuer`, `--user-token-audience` in mandrel-web (flag-drift CI).
- [ ] **`enforce-dpop` Not Implemented**: The spec field defaults to `true` and mandrel-spec docs present it as a control, but Collet has no DPoP code. **Decided 2026-11-09: implement it** (RFC 9449 proof bound to the user token's `cnf.jkt`). Needs a design for carrying the DPoP proof over gRPC, since `CompoundIdentity` has no field for it today.

- [ ] **Release Plumbing** (release candidate done 2026-11-09): mandrel-go tagged `v1.1.0-rc.1` (`064baa3`) and Collet pins it (`7c01a2a`); standalone build, race tests and `podman build` pass. All five feature branches are pushed and carry the coordinated tag `poi-core-01-rc.1`. Remaining: follow the `CONTRIBUTING.md` landing order. Note: because `v1.1.0-rc.1` exists, semverbot will release mandrel-go as `v1.1.1` (patch) or `v1.2.0` (minor), not `v1.1.0`; delete the rc tag before merging if `v1.1.0` matters, then re-pin Collet to the released tag. The DPoP proto change must merge in mandrel-spec and mandrel-go back to back because of `proto-drift`.
  - [ ] Collet's `flag-drift` CI fails on the pushed branch until mandrel-web documents the five new flags.
- [ ] **Receipt Propagation**: The CIR is stored in a Go `context.Value`, which gRPC does not transmit. Attach it to outgoing metadata and/or the response so the target and caller can see it.
- [x] **Receipt Semantics**: The CIR is minted before forwarding. Either document it as admission evidence only, or add a separate completion record after the target responds.
- [ ] **Metadata Separation on SUPERCEDE**: Wholesale replacement drops non-executable keys (trace, tenant, routing). Split executable parameters from metadata, replace only the former, then compare exactly before forwarding.
- [x] **Unknown-Outcome Handling**: A target error after consumption burns the intent with no record beyond telemetry. Record the consumed/unknown state for reconciliation.
- [x] **Signature Malleability**: The DER parser ignores trailing bytes, and raw vs. DER re-encoding changes the node hash without invalidating the signature. Use strict parsing.

### 2.5 Second Adversarial Review (Post-rc.2) — Priority Queue

Ordered by severity (Critical -> High -> Medium):

- [x] **1. [Critical] Multi-Tier / Multi-Matrix Policy Evaluation & Action Binding** (`mandrel-collet/pkg/enforcement/layers.go`):
  - Threshold tier evaluation loops over every matching tier in order (`50.00` then `500.00`), consuming the single `PoiEnvelope` on the lowest matching tier and failing on the next tier in the same matrix. Select the most restrictive matching tier per matrix (deny > highest required tier / min-approvals challenge > autonomous).
  - Verify `ico.AuthorizationDetails.Type == attributeName` (via `poi.WithChallengeAction(attributeName)`) so an approval for one governed attribute cannot satisfy a challenge for another attribute.
  - Ensure `IntentLayer` and `PolicyMatrixLayer` do not silently collide on the same `req.Identity.PoiEnvelope`.
- [x] **2. [Critical] Atomic Head-Only Attestation Consumption & Multi-Hop Chain Replay Bug** (`mandrel-collet/pkg/enforcement/layers.go`, `ledger.go`, `redisstore.go`):
  - `consumeAttestations(ctx, result.VerifiedSigners)` iterates over all signers (`seq: 1..n`) and runs before `IntentLedger.Admit`. In a multi-hop chain (`R0 -> R1 -> R2`), `R1`'s PSEA `jti` and PSEA/WebAuthn counter were already consumed when `[R0, R1]` was admitted as `PENDING`, so submitting `[R0, R1, R2]` always fails on `R1`!
  - Only consume attestations for newly admitted nodes, and fold PSEA `jti` consumption and counter advancement into the atomic `IntentLedger.Admit` operation (both in-memory and Redis Lua script) so failed/stale admissions never burn hardware counters or PSEA tokens.
- [x] **3. [High] PSEA Appended Node (`seq >= 2`) Challenge Binding** (`mandrel-go/pkg/poi/psea.go`, `attestations.go`, `draft-williams-oauth-poi-chained-state-01.md`):
  - At `seq >= 2`, `eat_nonce` and `psea_stepup_selection` bind only `prev.NodeHash` (`H_{i-1}`), leaving `node[i].ChallengeJWS` (`nodeICO.ChallengeID`) cryptographically unbound by the PSEA signature.
  - Bind the node challenge into PSEA tokens when `node.ChallengeJWS` is present (e.g., include `challenge_id` in `psea_stepup_selection` or derive `eat_nonce` from both `prev.NodeHash` and `node.ChallengeJWS` when an explicit node challenge is carried), and update `draft-williams-oauth-poi-chained-state-01.md` to match.
- [x] **4. [High] `SUPERCEDE` Occurrence Key Stability & `MemoryIntentLedger` Leak** (`mandrel-collet/pkg/enforcement/layers.go`, `ledger.go`):
  - Track the occurrence mapping across parameter replacements so retries/reapprovals after a `SUPERCEDE` resolve to the same `intent_id`.
  - Namespace `MemoryIntentLedger.occurrenceOf` by `scopedIntent(namespace, intentID)` and clean up `occurrenceOf` on completion.
- [x] **5. [High] `UserTokenVerifier` JWT `typ` Validation, Subject Extraction, and `all-of` Scopes** (`mandrel-collet/pkg/enforcement/usertoken.go`, `layers.go`):
  - Reject KCTs (`poi+jwt;kind=kct`) or PoI artifacts re-presented as user access tokens by checking `typ` (accepting `JWT`, `at+jwt`, or empty, and rejecting `poi+jwt*`).
  - Enforce `all-of` scope semantics in `checkScopes` (per 2.4 decision) and expose verified `Sub` so `ScopeLayer` / `PolicyMatrixLayer` can enforce subject continuity in synchronous single-approver flows.
- [x] **6. [High] Tier 1 KCT Audience (`kcert.aud`), Issuer (`kcert.iss`), Non-Empty `sub`, and `auth_time` (`max_age`) Verification** (`mandrel-go/pkg/poi/attestations.go`, `types.go`, `verifier.go`):
  - Support RFC 7519 string-or-array `aud` on `KeyCertificationTokenClaims` and enforce that when `kcert.aud` is non-empty, `ico.iss` is in `kcert.aud` (`ErrAudienceMismatch`).
  - Reject empty `kcert.sub` and empty `kcert.iss` (`ErrMalformedEnvelope` / `ErrInvalidKCTSignature`), add optional `WithTrustedIdPIssuer` and `WithMaxAuthAge` verifier options, and wire `ErrSessionMaxAgeExceeded` (`t_eval - kcert.auth_time > max_age`).
- [x] **7. [High] Root vs. Per-Node Challenge Handling at `seq == 1` and All-Challenge Consumption** (`mandrel-go/pkg/poi/verifier.go`, `types.go`):
  - Disallow `node[1].ChallengeJWS` when it conflicts with `R0.ChallengeJWS` unless `R0` is explicitly superseded by a step-up challenge, and expose all unconsumed challenge IDs in `VerificationResult` so no challenge in a chain can bypass consumption.
- [x] **8. [Medium] Legacy Node Deprecation / Strict Container Hash & `prior_chain` Signer Attribution** (`mandrel-go/pkg/poi/canonical.go`, `types.go`, `verifier.go`, `layers.go`):
  - Record verified signer `sub` and attained `assurance_tier` on `prior_chain` nodes (or validate container node hashes strictly) so Signing Vaults can display who signed prior Tier 2/3 nodes per Chained Draft Section 4.3.
- [x] **9. [Medium] Canonical Low-S ECDSA & Strict ASN.1 DER Signature Parsing** (`mandrel-go/pkg/poi/signer.go`, `webauthn.go`):
  - Reject high-S (`s > N/2`) ECDSA signatures in `VerifyJWS` and `verifyASN1OrRawP256`, normalize `SignJWS` to emit low-S (`s <= N/2`), and reject trailing bytes or non-minimal DER integers in `webauthn.go`.
- [x] **10. [Medium] Multi-Node Chain Admission Semantics in `decideAdmission`** (`mandrel-collet/pkg/enforcement/ledger.go`, `redisstore.go`):
  - Support both incremental hop-by-hop admission (`PENDING` head CAS) and complete multi-approver chains submitted in a single call when `st` is `IntentNone` or `IntentFailed` (consuming all carried challenges and attestations atomically).
- [x] **11. [Medium] Redis Cluster `CROSSSLOT` Fix in `outcomeScript`** (`mandrel-collet/pkg/enforcement/redisstore.go`):
  - Avoid deleting `occ` (which hashes to a different Redis Cluster slot and is not in `KEYS`) inside `outcomeScript`; return the `occurrence` key from `outcomeScript` and delete it via the client (or handle occurrence state via the intent state check).
- [x] **12. [Medium] `IntentLayer` vs. `PolicyMatrixLayer` Envelope Isolation** (`mandrel-collet/pkg/enforcement/layers.go`):
  - Ensure a PoI envelope is verified against the specific layer/attribute that issued the challenge and is not double-consumed across layers in the same request.

### 2.6 Third Adversarial Review (2026-11-09) — Open Items

Fixed in this pass (committed on the feature branches): plain-decimal thresholds (NaN and hex floats no longer skip a challenge), approvals evaluated at the Resource Server's attested `admitted_at` in chained envelopes, and `display_facts` covering every parameter. Details of the remaining findings are in the untracked `REVIEW.local.md`.

- [ ] **Approval binds `context` only**: `task_payload` and the originating request are not bound by the approval. Needs a design decision (payload as a parameter, a separate digest, or documenting context as the only executable input).
- [ ] **Pending quorum cannot be resumed** after the escalation challenge is lost or expires; needs mint-on-request and a stored chain.
- [ ] **Denial after admission strands the intent**; the intent and matrix layers also cannot both challenge one request.
- [ ] **`REJECT` is not recorded**; a rejected challenge can still be approved by another signer.
- [ ] **Unknown-outcome block is escapable** through the agent-supplied turn ID, extra context keys, or the 24-hour occurrence expiry.
- [ ] Reopen 2.5 items 1, 2, 4, 6, 9, 10 and 12: not implemented as checked.
- [ ] Library ignores `ico.required_tier`; WebAuthn challenge is hashed over a re-serialized payload; escalation challenges grow about 2.3x per hop; approver authorization is thin; smaller items in `REVIEW.local.md`.
- [ ] **Release:** Collet's standalone build fails against the `v1.1.0-rc.2` pin (it needs `VerifiedSigner.AdmittedAt` and `PriorSigners`). Cut a mandrel-go release candidate and re-pin before the next collaborator snapshot.
- [ ] mandrel-spec `docs/extensions.md` (all-of scope semantics) is edited but uncommitted, awaiting approval per its AGENTS.md.
- [ ] Rebuild the draft outputs (`make`) and run idnits: the core and chained-state `-01` sources changed after the last build.

---

## 3. Test Vectors & Interoperability

- [x] **Test Vector Organization**: `psea-03-baseline-sample.json` lives in `mandrel-go/pkg/poi/testdata/interop/psea/` with a provenance README (moved from the parent repo's `testdata/` on 2026-11-09; byte-identical to the email attachment).
- [x] **Reference Verifier Test**: `mandrel-go/pkg/poi/psea_test.go` verifies the baseline token. Note: standalone only. The `iss`/`aud`/`op` checks happen in the test body, and the vector cannot pass through `VerifyEnvelope` until typed parameters land.
- [ ] **Baseline Vector Through the Envelope Path**: Verify the PSEA baseline token inside a full PoIE once typed parameters and the binding profile are in place.
- [x] **Vector Path Escapes mandrel-go**: `psea_test.go` now reads `testdata/interop/psea/` inside mandrel-go. Verified with a standalone copy of mandrel-go (`GOWORK=off go test ./...` passes) and `sync-vectors.sh --check` unaffected.
- [ ] **Upstream Conformance Vectors**: Mirror the 31 negative/positive conformance vectors from `psea-spec` into `mandrel-go/pkg/poi/testdata/interop/psea/conformance/` with the upstream commit recorded (previously planned for the parent repo `testdata/`).

---

## 4. Activity Log

Newest first. Record what was done, what was found, and what was decided.

### 2026-11-09

- **Third adversarial review and fixes.** Reviewed the post-rc.2 tree; 19 findings, 14 reproduced with throwaway tests. Fixed three on `feat/poi-reference-impl`: plain-decimal threshold parsing, admission-time evaluation of chained nodes (chained-state Sections 4.3 and 6 updated), and complete `display_facts` (core Section 5.2 gains Coverage and Display safety). mandrel-go `e47fec3` and mandrel-collet `2525e13` pushed; no tags. `scripts/verify-poi.sh` with `DEMO=1` passes except the Collet standalone build, which waits on a mandrel-go release. Open findings are in 2.6.
- **Published rc.2.** mandrel-go `v1.1.0-rc.2` on `5fd2bac`; Collet re-pinned (`87f17c5`); coordinated `poi-core-01-rc.2` on all five feature heads (spec `8e39e2d`, go `5fd2bac`, collet `87f17c5`, cli `9ff3d79`, demo `d346900`). Full verification, including all standalone builds and the podman demo, passed before publishing. Drafts' Implementation Status points at rc.2. The parent repository is not pushed.
- **Implemented the draft -01 code follow-ups (uncommitted).** mandrel-go: attestation container, canonical node hashes, per-node challenges with `prior_chain`, decoded-digest PSEA comparison, `display_facts` validation. Collet: occurrence-stable intent IDs, an atomic intent ledger (memory and Redis) with outcome tracking and completion records, quorum escalation with CAS. Demo vault emits containers. Drafts updated (`intent_outcome_unknown`, detached mode optional, `prior_chain` rule, Implementation Status). Correction from the user: `editable_schema` is unimplemented, not deprecated; restored as optional.
- **Chained-state -01 and a core node-hash definition (uncommitted).** Aligning the extension surfaced two protocol gaps: node hashes past `H0` were undefined, and escalation or step-up appends had no challenge to bind under core precondition 4. Both are now specified. Both drafts rebuild; idnits reports no warnings or errors.
- **Draft -01 corrections (uncommitted).** Sections 1, 5, 6.1, 6.3, 7, 8, 9.4, 9.6, 11 and a new Section 12 (Implementation Status). Rebuilt with kramdown-rfc and xml2rfc; idnits 3.3.0 reports no nits on the text and XML outputs. Decision: keep the `attestation` container as the normative wire format; the implementation's legacy fields are listed as a known gap.
- **Pushed all five feature branches and tagged `poi-core-01-rc.1`** for collaborator inspection (spec `8e39e2d`, go `064baa3`, collet `7c01a2a`, cli `9ff3d79`, demo `ac09f39`). The tag is non-semver on purpose: semverbot reads prerelease `v*` tags as the current version (verified against semverbot v1.7.2 source and blang/semver v4), so `v0.2.0-rc.1` style tags would have skewed Collet and mandrel-cli release numbers. The parent repository is not pushed.
- **Published mandrel-go `v1.1.0-rc.1`.** Pushed only the mandrel-go feature branch and tag; other feature branches remain local. Collet pinned to the tag and verified standalone and with `podman build`.
- **Tier 1 admission fixes (uncommitted).** Skew-window replay, random IDs, `challenge_id` replay key, challenge issuer check, Redis replay and counter store with explicit `--replay-store`, and tests. Demo runs against a Redis container by default (`REPLAY_STORE=memory` opt-out) and passes 8/8 in both modes; fixed demo cleanup, which leaked containers in memory mode because podman aborts multi-name stop/rm on a missing name. Release plumbing (tag mandrel-go, bump Collet pin) awaits confirmation because it publishes.
- **Re-signed the feature branches for DCO.** All five Mandrel repositories require `Signed-off-by` on every commit; 12 feature commits lacked it (8 from this session, plus mandrel-go `d7dd76e` and mandrel-collet `685f6b5`, `b96edbe`, `e870387` from earlier work). Rebased mandrel-go, mandrel-collet and mandrel-demo with `--signoff` on their existing bases (trees unchanged), then rewrote the parent's unpushed history so every submodule pointer and commit message references the re-signed commits. Pre-rewrite heads are kept as local `backup/pre-signoff` branches in those submodules and `backup/pre-signoff-main` here. The rule is recorded in the untracked `CLAUDE.local.md`.
- **Added mandrel-cli as a submodule** (`feat/poi-reference-impl`, in `go.work`, in `scripts/verify-poi.sh` and `CONTRIBUTING.md`). Moved `ValidateActions` out of `spec.LoadSpec` into the Collet loader so the CLI keeps its structured diagnostics; `LoadSpec` only parses. Found and fixed a second fail-open: the CLI Rego generator treated unknown actions as autonomous.
- **Removed `challenge-always`.** One action, `challenge`, now means a fresh Proof-of-Intent approval per request. Load-time validation in mandrel-go and runtime deny-by-default in Collet close a pre-existing fail-open where an unrecognized action (including typos) allowed the request. mandrel-go, Collet and mandrel-spec tests pass. Uncommitted; mandrel-spec needs approval and `-s`.
- **Brought mandrel-spec into the feature scope.** Added `scripts/verify-poi.sh` and the landing order to `CONTRIBUTING.md`. Full run with `DEMO=1` passes every check (8/8 demo scenarios); a run with the wrong expected branch fails all four branch checks and exits 1. mandrel-spec changes stay uncommitted pending approval.
- **Decisions.** Required scopes are all-of. DPoP will be implemented. Override tokens: option 1 accepted (retire). Implemented in mandrel-spec (schema descriptions, identity.md 2.3.4, v1-core example), draft -01 Section 9.1, and the Collet comment. Spec schema tests pass; draft -01 rebuilds clean under idnits. mandrel-spec commits require DCO sign-off (`-s`).
- **Migrated the PSEA sample into mandrel-go (uncommitted).** Moved `testdata/vectors/psea/psea-03-baseline-sample.json` from the parent repo to `mandrel-go/pkg/poi/testdata/interop/psea/` with a provenance README, repointed `psea_test.go`, and removed the parent `testdata/`. Decision: not mandrel-spec, because the sample is explicitly non-conformance and spec `vectors/` is a normative Core contract for metrology labs.
- **Committed submodule work on `feat/poi-reference-impl` (not pushed).** mandrel-go: `74826f9` tier 2/3 binding, `b9116b7` VerifyJWS nil key. mandrel-collet: `b46815d` override bypass removal, `5e22bae` tier 2/3 trust, `6896ac4` user token verification. mandrel-demo: `712ce60` demo gate, `d4c7f44` signed user tokens. Shared files were split by building intermediate versions into the index; each intermediate commit was built and tested in isolation.
- **Fixed the Collet scope check (uncommitted).** Replaced unverified claim parsing and raw-word matching with signed token verification and fail-closed startup. Collet tests (`go test -race`) pass, including 10 forgery cases and a startup configuration test; the demo gate passes 8/8 with two new forged-token scenarios. Found while tracing: `enforce-dpop` is declared but not implemented.
- **Fixed `mandrel-demo/scripts/demo-poi.sh` (uncommitted).** The committed script never passed a token; the orchestrator default was comma-separated while Collet parses space-delimited scopes, so all six scenarios failed at the scope layer while the script printed success (`|| true`). The script now asserts each outcome and exits non-zero on deviation; orchestrator default token fixed; README documents usage. Verified: 6/6 pass on tier 0 code; a spec with the threshold raised to $1000 fails 5/6 and exits 1.
- **Added `mandrel-demo` and `mandrel-spec` submodules.** mandrel-demo vets and builds against the tier 0 mandrel-go through `go.work`; it has no unit tests and the end-to-end demo script was not run. Decision: PoI feature work is edited only in the submodules; standalone clones under the Mandrel project directory stay on `main`.
- **Tier 0 fixes implemented (uncommitted)** in `mandrel-go` and `mandrel-collet` on `feat/poi-reference-impl`.
  - mandrel-go: new `attestations.go` (per-profile node verifiers and a shared signed-claims check), `tiers.go` (`TierRank`, `TierSatisfies`), `CredentialResolver`/`EnrolledCredential` replacing `KeyResolver`, `WebAuthnRelyingParty`, `AppraisePSEA`, `PSEANonceForParent`, `PSEASelectionCommitment`, `Node.AssertionPayload`, and new `VerifiedSigner` attestation fields. `VerifyWebAuthnProof` signature changed (unreleased API, introduced after v1.0.19).
  - mandrel-collet: override bypass removed, IdP self-key fallback removed, head-signer tier check, PSEA jti consumption and counter checks (`counters.go`), trust store loader (`truststore.go`), `--poi-trust-store` flag.
  - Tests: `go test -race` passes in both modules. mandrel-go has 21 new top-level tests (35 cases with subtests) replacing the two prior envelope tests; Collet has 7 new tests. Each negative case asserts its error code or denial reason.
  - Decision: override tokens fail closed because no format is specified anywhere; the old test asserted the bypass as a feature.
  - Decision: PSEA nonce = base64url(parent node digest); selection = base64url(SHA-256(JCS({decision, target_node_hash}))). Pending confirmation with the PSEA author.
- **Adversarial review of draft -01 and both submodules** against OAuth WG review feedback and the PSEA -03 baseline sample.
  - Scope: diffs since Collet 6488224 and mandrel-go 7ac18ba; the full `enforcePoIChallenge` path, `server.go` forwarding, the PSEA and WebAuthn verifier branches, and the -00 to -01 draft diff.
  - Ran `go test` in both submodules: all pass. `GOWORK=off go build` of Collet succeeds against v1.0.17, which revealed the release plumbing gap.
  - Wrote throwaway PoC tests against local mandrel-go. Confirmed WebAuthn decision relabel, PSEA cross-intent reuse, IdP-key fallback with no `exp`, PSEA SUPERCEDE keeping `R0`, and the parameter type mismatch.
  - Verified on Datatracker: the EP-RECEIPTS citation is correct; the PSEA citation has the wrong title, organization and date.
  - Outcome: reopened 7 previously checked items and added the new items above. Collaborator replies are gated on fixes.
- **Process decision**: commits in this repo and its submodules carry no Claude co-author or attribution trailer.
- **Prior work recorded in git** (`226a7da` .. `0515c1d`): P1/P2 Collet fixes, P3 consume-once tracker, namespaced tracker registry, P4 PSEA and WebAuthn verifier integration.
