# Verifying a release

A security tool that ships unsigned undercuts its own story. Every Argus
release is built by a public GitHub Actions workflow
([`release.yml`](https://github.com/zer0d4y5/argus/blob/main/.github/workflows/release.yml))
and carries three independent pieces of evidence:

- a **SHA-256 checksums** file (`checksums.txt`) listing every artifact,
- a **keyless cosign signature** over that checksums file
  (`checksums.txt.sig` + `checksums.txt.pem`), bound to the workflow's
  Sigstore identity and logged in the public Rekor transparency log, and
- an **SLSA build-provenance attestation** on each archive: a signed
  statement tying the artifact to this repository, workflow, and commit.

Plus a **CycloneDX SBOM** per archive (`*.cyclonedx.json`), so you can see
exactly what each binary is built from.

None of this needs a trusted key from us: the signatures are keyless
(Sigstore), so verification checks the identity of the workflow that built
the release, not a key we could lose.

## 1. Checksum

Download the archive for your platform and `checksums.txt`, then:

```bash
sha256sum --check --ignore-missing checksums.txt
```

## 2. Signature over the checksums (cosign)

This proves the checksums file was produced by the Argus release workflow.
Install [cosign](https://docs.sigstore.dev/system_config/installation/), then:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/zer0d4y5/argus/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
```

A successful verify plus a matching checksum means the archive is exactly
what the workflow built.

## 3. Build provenance (SLSA)

The provenance attestation is the strongest claim: it records how and where
the binary was built. Verify it with the GitHub CLI:

```bash
gh attestation verify argus_<version>_<os>_<arch>.tar.gz \
  --repo zer0d4y5/argus
```

This confirms the artifact was produced by this repository's release
workflow, at a specific commit, and was not built or tampered with
elsewhere.

## 4. Bill of materials (SBOM)

Each archive ships a CycloneDX SBOM listing its components. Feed it to any
SCA or policy tool, or scan the release with Argus itself:

```bash
argus sbom .   # your own project's SBOM; see docs/sbom.md
```

## What a dev build reports

A binary built locally with `go build` or `go install` honestly reports
itself as a development build with no release provenance:

```
$ argus --version
argus version dev (commit none, built unknown)
```

A verified release stamps the real version, commit, and build date, which
match the provenance attestation above.
