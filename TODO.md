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
- [ ] **PSEA Schema Precision Update**:
  - [ ] Update Section 6.3.3.2 and Section 7.1 to explicitly document the JWS header distinction: media type `application/psea+jwt` vs. protected header `typ: "psea-proof+jwt"`.
  - [ ] Document the 300-second temporal lifetime (`exp - iat = 300`) and verification clock anchoring against `cir.received_at`.
- [ ] **Informative Citations Polish**:
  - [ ] Validate final Datatracker URIs and revision targets for `draft-yossif-psea-03` and `draft-schrock-ep-authorization-receipts-13`.

---

## 2. Reference Implementation Track (`mandrel-collet` on `feat/poi-reference-impl`)

- [x] **Submodule Setup**: Added `mandrel-collet` submodule via native SSH (`git@gitlab.com:the-mandrel-project/mandrel-collet.git`).
- [x] **Working Branch**: Created and checked out `feat/poi-reference-impl` from `main` (`6488224`).
- [ ] **Bug Fix: `CommittedParamsHash` Assignment**:
  - [ ] Correct `mandrel-collet/pkg/enforcement/layers.go` (line 597) to compute `poi.HashParams(result.EffectiveParams)` instead of copying `result.HeadNodeHash`.
- [ ] **Bug Fix: Complete Parameter Replacement on `SUPERCEDE`**:
  - [ ] Replace `req.Context` completely with `result.EffectiveParams` in `layers.go` (line 573) rather than shallow map merging, ensuring omitted keys from `R0` are purged.
- [ ] **Feature: Stateful Consume-Once Check**:
  - [ ] Add stateful replay detection (tracking consumed `intent_id` / `jti`) wrapping stateless `VerifyEnvelope`.
- [ ] **Feature: PSEA Attestation Verifier Integration**:
  - [ ] Add verifier unpacker for `application/psea+jwt` (`typ: "psea-proof+jwt"`) using the baseline vector.
  - [ ] Verify claims: `psea_payload_hash`, `psea_uv.verified == true`, and P-256 public key verification.
- [ ] **Feature: Passkey / WebAuthn Verification**:
  - [ ] Replace stub in `mandrel-go` returning `unsupported assurance tier` with WebAuthn assertion verification.
- [ ] **Regression & Conformance Test Suite**:
  - [ ] Add test cases for parameter omission on SUPERCEDE.
  - [ ] Add test cases for replay rejection.
  - [ ] Ingest the PSEA baseline test vector (`testdata/vectors/psea/psea-03-baseline-sample.json`).

---

## 3. Test Vectors & Interoperability

- [x] **Test Vector Organization**: Relocate `psea-03-baseline-sample.json` into structured `testdata/vectors/psea/`.
- [ ] **Reference Verifier Test**: Create a standalone Go/Python test script verifying `psea-03-baseline-sample.json` against the public JWK.
- [ ] **Upstream Conformance Vectors**: Mirror the 31 negative/positive conformance vectors from `psea-spec` into `testdata/vectors/psea/conformance/`.

---

## 4. Collaborator Engagement

- [ ] **Reply to the PSEA author**:
  - [ ] Confirm receipt of `psea-03-baseline-sample.json`.
  - [ ] Acknowledge the `typ: "psea-proof+jwt"` vs. media type distinction.
  - [ ] Confirm inclusion in `-01` draft Section 6.3.3.2, 7.1, and Acknowledgements.
- [ ] **Reply to a reviewer**:
  - [ ] Notify when `feat/poi-reference-impl` branch and regression tests are published on GitLab for review.
