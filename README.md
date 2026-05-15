# tatara

**A daemonless, zero-privilege Kubernetes image builder with built-in supply-chain attestations.**

Build OCI/Docker images from a Dockerfile, inside a container or Kubernetes pod, without a Docker daemon and without privileged capabilities — and emit a SLSA Provenance v1.0 attestation and SPDX/CycloneDX SBOM as part of every build.

[![Go Report Card](https://goreportcard.com/badge/github.com/iahsanGill/tatara)](https://goreportcard.com/report/github.com/iahsanGill/tatara)

## What's different

`tatara` is a fork of [`kaniko`](https://github.com/GoogleContainerTools/kaniko) (archived by Google in June 2025) and [`osscontainertools/kaniko`](https://github.com/osscontainertools/kaniko) (the community-maintained continuation). It is **not** another caretaker fork — it adds features no other public fork has:

| Capability | tatara | kaniko (archived) | osscontainertools/kaniko |
|------------|--------|-------------------|--------------------------|
| Daemonless, zero-privilege image builds | ✓ | ✓ | ✓ |
| Runs under K8s PSA `restricted` | ✓ | ✓ | ✓ |
| `RUN --mount=type=secret` / `type=cache` / `type=bind` | partial *(coming)* | ✗ | ✓ |
| **Continue probing cache after a miss** | ✓ | ✗ | ✗ |
| **Native SPDX 2.3 + CycloneDX 1.6 SBOM generation** | ✓ | ✗ | ✗ |
| **Native SLSA Provenance v1.0 attestations** | ✓ | ✗ | ✗ |
| Multi-arch single-invocation builds | planned | ✗ | ✗ |
| Streaming snapshotter (OOM fix) | planned | ✗ | ✗ |

If you only need maintenance + bug fixes for kaniko, use [`osscontainertools/kaniko`](https://github.com/osscontainertools/kaniko). If you need supply-chain attestations out of the box, use `tatara`.

## How tatara works

Same core model as upstream kaniko: pull the base image, extract its filesystem to `/` of the tatara container, execute each Dockerfile command natively, snapshot filesystem changes between commands to compose layers, push the resulting image. No nested containers, no `CAP_SYS_ADMIN`, no Docker socket.

What tatara adds on top:

1. **Cache that survives transient misses.** A single missed layer no longer disables the cache for the rest of the stage. See [`--cache-probe-after-miss`](#flag---cache-probe-after-miss).
2. **SBOM emission after the build.** Between the build phase and the push phase, tatara scans the assembled root filesystem with [syft](https://github.com/anchore/syft) (excluding tatara's own working dirs) and writes an SPDX or CycloneDX SBOM. See [`--sbom-format`](#flag---sbom-format).
3. **SLSA Provenance v1.0 attestations.** In the same hand-off, tatara emits an in-toto v1 Statement wrapping a SLSA Provenance v1.0 predicate — recording the build inputs, builder identity, and timing. See [`--provenance-path`](#flag---provenance-path).

The SBOM and provenance are written as JSON files. Attaching them as OCI referrers and signing with cosign is on the roadmap.

## Quick start

```shell
docker run \
  -v $(pwd):/workspace \
  -v $(pwd)/out:/output \
  ghcr.io/iahsangill/tatara:latest \
  --context dir:///workspace \
  --dockerfile Dockerfile \
  --destination my.registry/my-image:v1.0 \
  --sbom-format spdx-json --sbom-path /output/sbom.spdx.json \
  --provenance-path /output/provenance.json
```

After the build:

- `out/sbom.spdx.json` — valid SPDX 2.3 listing every OS-package and language-manifest package in the image
- `out/provenance.json` — in-toto v1 statement with SLSA Provenance v1.0 predicate

```shell
jq -r '.predicateType' out/provenance.json
# => https://slsa.dev/provenance/v1
```

For drop-in compatibility with kaniko users: tatara preserves all `/kaniko/*` container paths (`/kaniko/.docker/config.json`, `/kaniko/ssl/certs`, etc.) and all CLI flags. Existing `gcr.io/kaniko-project/executor` Pod specs work with just an image-name swap.

## Notable flags

#### Flag `--cache-probe-after-miss`

Default: `true`. Keeps probing the cache for subsequent layers after a cache miss instead of stopping at the first one. The legacy kaniko behavior was the opposite: a single transient miss disabled cache lookups for the rest of the stage. Set to `false` to restore legacy behavior.

#### Flag `--sbom-format`

`spdx-json` | `cyclonedx-json` | empty (disabled). Requires `--sbom-path`.

#### Flag `--sbom-path`

Absolute path on the tatara filesystem where the generated SBOM is written. Required when `--sbom-format` is set.

#### Flag `--provenance-path`

Absolute path where an in-toto v1 + SLSA Provenance v1.0 attestation is written as JSON. Empty disables provenance generation.

The attestation records:

- **subject** — every destination tag and the image's sha256 digest
- **buildDefinition.buildType** — `https://github.com/iahsanGill/tatara/builds/dockerfile/v1`
- **buildDefinition.externalParameters** — destinations, dockerfile path, source context, build args, target, platform
- **buildDefinition.internalParameters** — cache, snapshot mode, reproducible flag, etc.
- **runDetails.builder** — builder URI and tatara version
- **runDetails.metadata** — random 128-bit invocation ID plus UTC start/finish timestamps

All other flags from upstream kaniko are preserved unchanged — see the kaniko documentation for `--build-arg`, `--cache`, `--destination`, `--target`, etc. Eventually this README will subsume them; for now, anything not listed here behaves as upstream documents it.

## Build from source

```shell
make out/executor
```

Produces a statically linked Linux binary at `out/executor`.

To build the container image:

```shell
make images REGISTRY=ghcr.io/iahsangill
```

## Status

- Source archive: forked from upstream kaniko v1.24.0 (HEAD at archival).
- Active: yes — see the [issue tracker](https://github.com/iahsanGill/tatara/issues) for the roadmap.
- API stability: pre-1.0. The CLI flags listed above are stable; internal Go APIs are not.

## Relationship to upstream

`tatara` keeps the upstream Go type names (`KanikoOptions`, `KanikoDir`, etc.) and container paths (`/kaniko/*`) unchanged. This is deliberate: it makes cherry-picking fixes from [`osscontainertools/kaniko`](https://github.com/osscontainertools/kaniko) painless, and lets existing kaniko users adopt tatara with only an image-name swap. Only the Go module path (`github.com/iahsanGill/tatara`), binary identity, and the supply-chain features (SBOM / SLSA / cache-probe) are net-new.

When this fork has fixes useful to upstream, they are submitted there too. See [`osscontainertools/kaniko#703`](https://github.com/osscontainertools/kaniko/pull/703) for the cache-probe-after-miss fix being upstreamed.

## License

Apache License 2.0 — same as upstream. See [LICENSE](./LICENSE).

See [NOTICE](./NOTICE) for attribution to the original kaniko authors at Google and the `osscontainertools` community.
