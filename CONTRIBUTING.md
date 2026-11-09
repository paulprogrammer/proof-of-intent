# Contributing to the Proof-of-Intent (PoI) Specifications

Thank you for your interest in contributing to the **Cryptographic
Proof-of-Intent (PoI)** Internet-Drafts (`draft-williams-oauth-poi-core`
and `draft-williams-oauth-poi-chained-state`), maintained as part of
the [Mandrel Project](https://mandrelproject.ai).

Because the documents in this repository are formatted for submission
to the **Internet Engineering Task Force (IETF)** `oauth` Working
Group, all contributions (including GitHub Issues, Pull Requests, and
review comments) are **IETF Contributions** governed by the IETF
**Note Well** (BCP 78 and BCP 79) and [RFC 8874](https://www.rfc-editor.org/rfc/rfc8874).

---

## 1. IETF Note Well

This repository relates to activities of the Internet Engineering Task
Force (IETF). All material posted here (Issues, Pull Requests,
commits, and comments) is considered an **IETF Contribution**.

By participating in this repository, you agree to the IETF **Note
Well**:

* Any submission to the IETF intended by the Contributor for
  publication as all or part of an IETF Internet-Draft or RFC and any
  statement made within the context of an IETF activity is considered
  an "IETF Contribution". Such statements include oral statements in
  IETF sessions, as well as written and electronic communications made
  at any time or place, which are addressed to:
  * The IETF plenary session
  * The IESG, or any member thereof on behalf of the IESG
  * Any IETF mailing list, including the IETF list itself, any working
    group or design team list, or any other list functioning under IETF
    auspices
  * Any IETF working group or portion thereof
  * Any Birds of a Feather (BOF) session
  * The IAB or any member thereof on behalf of the IAB
  * The RFC Editor or the Internet-Drafts function
  * This GitHub repository
* All IETF Contributions are subject to the rules of
  [RFC 5378 (BCP 78)](https://www.rfc-editor.org/rfc/rfc5378) and
  [RFC 8179 (BCP 79)](https://www.rfc-editor.org/rfc/rfc8179).
* Statements made outside of an IETF session, mailing list, or other
  function, that are clearly not intended to be input to an IETF
  activity, group, or function, are not IETF Contributions in the
  context of this notice.
* A participant in any IETF activity is deemed to accept all IETF
  rules of process, as documented in Best Current Practices RFCs and
  IESG Statements.
* A participant in any IETF activity acknowledges that written, audio,
  video, and photographic records of meetings may be made and may be
  available to the public.

For full details, see: https://www.ietf.org/about/note-well/

---

## 2. How to Submit Feedback or Pull Requests

1. **Mailing List Discussion:** Substantive protocol design questions
   and Working Group discussions should also be raised on the IETF
   OAuth Working Group mailing list (`oauth@ietf.org`).
2. **GitHub Issues:** Open an Issue to report editorial nits, edge
   cases in the verification algorithm, or wire-format questions.
3. **Pull Requests:**
   * Maintain **100% pure 7-bit ASCII** across all Markdown files per
     [RFC 7997](https://www.rfc-editor.org/rfc/rfc7997) (use `->`, `<=`,
     `>=`, `--`, and `...` rather than Unicode arrows or em-dashes).
   * Preserve the `kramdown-rfc` YAML frontmatter at the top of
     `draft-williams-oauth-poi-core-00.md` and
     `draft-williams-oauth-poi-chained-state-00.md`.
   * Verify pure ASCII before submitting:
     ```sh
     LC_ALL=C grep -rn '[^ -~]' .
     ```

---

## 3. Reference Implementation Submodules

The PoI reference implementation spans four Mandrel repositories. They
are pinned here as Git submodules so that each draft revision maps to
exact implementation commits for the Implementation Status section
([RFC 7942](https://www.rfc-editor.org/rfc/rfc7942)).

| Submodule        | Role in PoI                                                   |
|------------------|---------------------------------------------------------------|
| `mandrel-go`     | Verifier library (`pkg/poi`): envelopes, attestation profiles |
| `mandrel-collet` | Enforcement proxy: challenge issuance, admission, replay      |
| `mandrel-demo`   | Mock IdP, mock Signing Vault, end-to-end demo scripts         |
| `mandrel-spec`   | Proto, policy schema, canonical test vectors                  |

Rules:

1. **Edit PoI feature work only in these submodules.** All PoI changes
   to the four repositories are made in the submodule working trees
   under this repository, on the `feat/poi-reference-impl` branch. Do
   not make PoI changes in standalone clones of the same repositories
   elsewhere on disk; those clones stay on `main` and receive PoI work
   only through merge requests from `feat/poi-reference-impl`.
2. **Never commit to `main` inside a submodule.** Use
   `feat/poi-reference-impl` or a dedicated branch.
3. **The parent repository may commit directly to `main`.** Record a
   submodule pointer update here when a submodule commit becomes part
   of the documented PoI implementation state.
4. **Workspace builds differ from release builds.** `go.work` at the
   repository root wires `mandrel-go`, `mandrel-collet`, and
   `mandrel-demo` together (`mandrel-spec` is not a Go module).
   Standalone builds (`GOWORK=off`, Docker, CI) resolve each module's
   `go.mod` pin and do not see unreleased `mandrel-go` changes until a
   tag is cut and the pin is bumped.

Setup after cloning:

```sh
git clone --recurse-submodules git@github.com:paulprogrammer/proof-of-intent.git
git submodule foreach 'git switch feat/poi-reference-impl || true'
```

---

## 4. Contact

* **Author:** Paul Charles Williams (`paul@barefootcoders.com`)
* **Organization:** Barefoot Coders, LLC
* **Project:** Mandrel Project (`https://mandrelproject.ai`)
