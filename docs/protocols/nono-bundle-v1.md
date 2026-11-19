# nono Bundle v1

A file bundle is an immutable directory containing a policy, its dependencies,
and any additional files covered by its signature. Its root `bundle.sig`
contains the complete signed inventory; there is no separate manifest file.
The outer directory name is not part of the signature.

```text
engineering/r7-<manifest-sha256>/
  bundle.sig
  policy.json
  groups.json
  profiles/profile-0.json
  packs/claude/package.json
  packs/claude/policy.json
  packs/claude/bundle.sig
  packs/claude/skills/review/SKILL.md
```

The format uses a Sigstore-style bundle protocol: a Sigstore bundle v0.3 wraps
a DSSE envelope containing an in-toto Statement v1.
Each subject names a file and its SHA-256 digest. The nono predicate identifies
the policy and the local dependency bindings.

## Signature and inventory

`bundle.sig` has the standard Sigstore JSON fields:

* `mediaType`: `application/vnd.dev.sigstore.bundle.v0.3+json`.
* `verificationMaterial.publicKey.hint`: the enrolled platform key ID.
* `verificationMaterial.tlogEntries`: empty for this keyed-signing version.
* `dsseEnvelope.payloadType`: `application/vnd.in-toto+json`.
* `dsseEnvelope.payload`: standard padded base64 of the exact statement bytes.
* `dsseEnvelope.signatures`: one signature, with standard padded base64 `sig`.

The signature is ECDSA P-256/SHA-256, encoded as ASN.1 DER, over the existing
DSSE pre-authentication encoding of the payload type and decoded payload.
The verifier obtains the trusted public key from authenticated enrollment,
not from the signature file. The key hint selects that key; it does not confer
trust. The signed publisher name is a display label, currently `nolabs, Inc.`.
This version needs no Fulcio certificate, Rekor log or public network request
to verify the files. It does not claim transparency-log inclusion.
The v1 signature wrapper accepts only the fields above. Conflicting signature
types, certificates, timestamps, nonempty log entries and unknown wrapper fields
are rejected rather than ignored.

The decoded payload has this shape (subjects abbreviated):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "policy.json",
      "digest": {"sha256": "<64 lowercase hex characters>"},
      "annotations": {"size": "420"}
    }
  ],
  "predicateType": "https://nono.sh/attestation/bundle/v1",
  "predicate": {
    "name": "Engineering",
    "publisher": "nolabs, Inc.",
    "revision": 7,
    "entrypoints": {
      "policy": "policy.json",
      "groups": "groups.json"
    },
    "profiles": {"profile-0": "profiles/profile-0.json"}
  }
}
```

Every content file appears exactly once, including nested manifests and
signatures. Only the root `bundle.sig` is excluded. A nested pack remains
byte-for-byte intact: its signature is another file authenticated by the outer
inventory. Outer verification establishes platform approval of those bytes;
independent publisher verification is a separate operation requiring that
publisher's trusted identity.

`entrypoints.policy` names the assigned source profile. `entrypoints.groups`
names a JSON map of referenced policy-group definitions, or `{}`. `profiles`
maps inheritance identifiers used in `extends` to included profile files.
An inheritance identifier absent from this map is an error; the device must
not search local profiles, built-ins or a registry to satisfy it. Path variables,
conditional rules and OS overrides remain unresolved until the device applies
the existing profile resolver. Local package groups are not loaded.

The bundle ID is `sha256:<hex>` of the exact decoded statement bytes. It is
independent of signature randomness and archive compression. Producers serialize
the statement deterministically; verifiers hash and authenticate the original
bytes, without reserializing them.

## Verification rules

Verify the signature, statement type and predicate version, then verify the
complete inventory before consuming any profile. Missing, extra, changed or
duplicate files fail verification. Size annotations are decimal byte counts
encoded as strings; SHA-256 is the only supported subject digest algorithm.

Paths are ASCII, relative to the bundle root, slash-separated, at most 1,024
bytes and 64 components. Empty components, `.` and `..`, backslashes, colons,
control characters, case-insensitive collisions and file/directory conflicts
are refused. The root signature filename is reserved case-insensitively.
Symlinks and special files are unsupported. Empty directories have no meaning.
The limits are 1,000 content files, 32 MiB total decoded content and
256 KiB of decoded statement bytes. The HTTP response is capped at 48 MiB,
including base64 encoding and the signed inventory. Producers and consumers
enforce these bounds; excess content is refused rather than truncated.
Unsupported predicates, metadata fields or policy entrypoints fail closed.

Referenced packs are included under `packs/<namespace>/<name>/`, including every
regular file in their package store: manifests, hooks, skills, assets, wiring,
supporting files and available upstream signatures. Artifact paths are restored
to the original names declared in `package.json`; their bytes are unchanged.
Transitive pack references and explicit `packs` entries are collected once per
pack. Missing declared artifacts, symlinks, special files and limit violations
fail export rather than produce a partial pack.

The separate `policy.json` and `profiles/` files are policy projections with
closed inheritance bindings and runtime pack references removed. Clients use
these projections and the delivered groups for sandboxing. Included pack files
are verified and cached but do not install agent configuration, execute hooks or
activate skills. Hook declarations are retained in the signed policy sources,
including inherited profiles and OS overrides. Consumers clear host and session
hooks only from the in-memory managed runtime profile before launch; the signed
sources and cached pack files remain unchanged. New execution semantics require
their own compatibility and permission decisions; authenticating a file never
authorizes its execution.

## Managed delivery v2

Request `protocol_version: "2"` through the existing enrollment-authenticated
`POST /api/v1/policy/refresh`. Enrollment request authentication remains v1;
the HTTP path and authentication-header version are unchanged.

The response retains the existing signed assignment envelope (`algorithm`,
`key_id`, base64url `payload`, base64url `signature`) and adds `bundle` beside
it. The fresh signed claims retain tenant, subject, request ID, issuance time,
mode and assignment version. Their `policy` contains profile ID, revision,
grant-delta version and `content_digest`, now the manifest's bundle ID.
There is no embedded `profile_json` or file content inside v2 claims.

The separate `bundle` contains:

```json
{
  "signature": {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
  "files": {"policy.json": "<standard padded base64 of file bytes>"}
}
```

The signature object above is abbreviated; it is the full `bundle.sig` JSON.
File bytes travel inline initially. The signed manifest and its bundle ID stay
the same if a later transport fetches files individually by digest or delivers
an archive. No temporary download URL is a content identity.

The client first verifies the fresh assignment using the pinned enrollment
key and existing request/freshness checks. It then verifies the file bundle
using that key, checks that the decoded statement digest equals the assignment's
`content_digest`, and checks its signed revision against the assignment.
Audit-only responses contain no bundle. Advisory and enforced responses carry
the same complete bundle; the signed mode determines whether local overrides
are permitted. See [enforced startup](managed-policy-v2.md#enforced-startup).

The platform computes v2 assignment identity from mode, resolution provenance,
profile ID, revision, grant-delta version and manifest digest. Randomized bundle
signatures do not cause assignment changes. Signature and assignment are
different authorities: an old bundle may remain cryptographically valid while
a fresh assignment no longer permits its use.

Verified files are staged together and published into the existing scoped
policy cache under `<platform/tenant/device scope hash>/<policy slug>/r<revision>-<digest>/`.
The slug is a readable, bounded ASCII rendering of the signed name; the digest
is the identity. Files are stored once, with the assignment cache retaining the
signature and reloading content from that directory. Cached inspection and
subsequent launches reverify the inventory. A cache is not offline launch
authority: every managed default launch still needs a fresh platform response.

This is the only managed-policy delivery format. Unsupported refresh versions
and raw profile documents are rejected. Obsolete cached response versions are
discarded while preserving the pinned key and remembered management mode;
managed startup still requires a fresh valid assignment. Upgrade the platform,
its nono exporter and clients together. Export failure never selects another
format or local policy.

## Building and conformance

`nono profile show <profile-path> --format bundle` produces an unsigned
`{statement, files}` export for platform signing. It uses the profile dependency collector and resolver. The export has no revision until
the platform adds the deployed revision and signs it. It is not trusted until
signed and verified.

`tests/fixtures/nono-bundle-v1.json` is mirrored in the platform repository's
`fixtures/` directory. It covers a fresh-assignment envelope, keyed Sigstore
inventory, inherited policy, skill bytes and an opaque nested publisher
signature. Tests cover signature binding, inventory tampering, path rejection,
directory round-trips and managed CLI launch/cache verification.
