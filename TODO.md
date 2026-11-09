# Proof-of-Intent (PoI) Work Tracker

## 1. Specification Track (`draft-williams-oauth-poi-core-01`)

- [x] **Initialize -01 Draft**: Cloned source, updated document header, and verified with `idnits`.
- [x] **Pre-Commit Historical Draft Locking**: Enforced immutable historical draft rules via `.githooks/pre-commit`.
- [x] **Attestation Profile Conformance (Section 6.3)**:
  - [x] Formulated the 5 abstract attestation preconditions (WYSIWYE, Lineage, Freshness, Signer/Assurance, Deterministic Extraction).
  - [x] Added applicability assessments for Session PoP, PSEA (`application/psea+jwt`), and Direct WebAuthn.
- [x] **SUPERCEDE Parameter Replacement (Section 6.2 & 9.5)**:
  - [x] Codified the full replacement invariant (omitted parameters from `R0` must not survive into executable input).
- [x] **Application Crash Recovery Demarcation (Section 9.4)**:
  - [x] Clarified boundary between cryptographic intent verification and application-level 2PC/idempotency.
- [x] **PSEA Schema Precision Update**:
  - [x] Update Section 6.3.3.2 and Section 7.1 to explicitly document the JWS header distinction: media type `application/psea+jwt` vs. protected header `typ: "psea-proof+jwt"`.
  - [x] Document the 300-second temporal lifetime (`exp - iat = 300`) and verification clock anchoring against `cir.received_at`.
- [x] **Informative Citations Polish**:
  - [x] Validate final Datatracker URIs and revision targets for `draft-yossif-psea-03` and `draft-schrock-ep-authorization-receipts-13`.

---

## 2. Reference Implementation Track (`mandrel-collet` on `feat/poi-reference-impl`)

- [x] **Submodule Setup**: Added `mandrel-collet` and `mandrel-go` submodules via native SSH (`git@gitlab.com:the-mandrel-project/mandrel-collet.git`, `mandrel-go.git`).
- [x] **Working Branches**: Created and checked out `feat/poi-reference-impl` in both `mandrel-collet` and `mandrel-go`.
- [x] **Bug Fix: `CommittedParamsHash` Assignment**:
  - [x] Correct `mandrel-collet/pkg/enforcement/layers.go` to compute `poi.HashParams(result.EffectiveParams)` instead of copying `result.HeadNodeHash`.
- [x] **Bug Fix: Complete Parameter Replacement on `SUPERCEDE`**:
  - [x] Replace `req.Context` completely with `result.EffectiveParams` in `layers.go` rather than shallow map merging, ensuring omitted keys from `R0` are purged.
- [x] **Feature: Stateful Consume-Once Check**:
  - [x] Add stateful replay detection (tracking consumed `intent_id` / `jti`) wrapping stateless `VerifyEnvelope`.
- [x] **Feature: PSEA Attestation Verifier Integration**:
  - [x] Add verifier unpacker for `application/psea+jwt` (`typ: "psea-proof+jwt"`) using the baseline vector.
  - [x] Verify claims: `psea_payload_hash`, `psea_uv.verified == true`, and P-256 public key verification.
- [x] **Feature: Passkey / WebAuthn Verification**:
  - [x] Replace stub in `mandrel-go` returning `unsupported assurance tier` with WebAuthn assertion verification.
- [x] **Regression & Conformance Test Suite**:
  - [x] Add positive test cases for parameter omission on SUPERCEDE.
  - [x] Add positive and negative test cases for CIR `CommittedParamsHash` calculation and in-flight parameter tampering detection.
  - [x] Add positive, negative, TTL expiration, and concurrent race test cases for replay rejection.
  - [x] Ingest the PSEA baseline test vector (`testdata/vectors/psea/psea-03-baseline-sample.json`).

---

## 3. Test Vectors & Interoperability

- [x] **Test Vector Organization**: Relocate `psea-03-baseline-sample.json` into structured `testdata/vectors/psea/`.
- [x] **Reference Verifier Test**: Create a standalone Go test verifying `psea-03-baseline-sample.json` against the public JWK (`mandrel-go/pkg/poi/psea_test.go`).
- [ ] **Upstream Conformance Vectors**: Mirror the 31 negative/positive conformance vectors from `psea-spec` into `testdata/vectors/psea/conformance/`.

---

## 4. Collaborator Engagement

- [ ] **Reply to the PSEA author**:
  - [ ] Confirm receipt of `psea-03-baseline-sample.json`.
  - [ ] Acknowledge the `typ: "psea-proof+jwt"` vs. media type distinction.
  - [ ] Confirm inclusion in `-01` draft Section 6.3.3.2, 7.1, and Acknowledgements.
- [ ] **Reply to a reviewer**:
  - [ ] Notify when `feat/poi-reference-impl` branch and regression tests are published on GitLab for review.
