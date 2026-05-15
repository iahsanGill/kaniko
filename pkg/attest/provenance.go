/*
Copyright 2026 The Kaniko Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package attest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/iahsanGill/tatara/pkg/config"
	"github.com/iahsanGill/tatara/pkg/version"
	"github.com/pkg/errors"
)

// buildStatement assembles the in-toto Statement + SLSA Provenance v1.0
// predicate from the kaniko build configuration and timing.
//
// imageDigest is the sha256 digest of the produced image, with or without
// the "sha256:" prefix.
func buildStatement(opts *config.KanikoOptions, imageDigest string, startedAt, finishedAt time.Time) (*Statement, error) {
	digestHex, err := normalizeSHA256(imageDigest)
	if err != nil {
		return nil, errors.Wrap(err, "normalizing image digest")
	}

	subjects := make([]Subject, 0, max(1, len(opts.Destinations)))
	switch {
	case len(opts.Destinations) > 0:
		for _, dest := range opts.Destinations {
			subjects = append(subjects, Subject{
				Name:   dest,
				Digest: map[string]string{"sha256": digestHex},
			})
		}
	default:
		// No destinations (--no-push without --destination) — still emit a
		// subject so the attestation is well-formed.
		subjects = append(subjects, Subject{
			Name:   "image",
			Digest: map[string]string{"sha256": digestHex},
		})
	}

	return &Statement{
		Type:          InTotoStatementV1,
		Subject:       subjects,
		PredicateType: SLSAProvenanceV1Predicate,
		Predicate: ProvenancePredicate{
			BuildDefinition: BuildDefinition{
				BuildType:          BuildTypeTataraDockerfileV1,
				ExternalParameters: externalParameters(opts),
				InternalParameters: internalParameters(opts),
			},
			RunDetails: RunDetails{
				Builder: Builder{
					ID: BuilderID,
					Version: map[string]string{
						"tatara": version.Version(),
					},
				},
				Metadata: Metadata{
					InvocationID: newInvocationID(),
					StartedOn:    startedAt.UTC(),
					FinishedOn:   finishedAt.UTC(),
				},
			},
		},
	}, nil
}

// externalParameters captures user-supplied build inputs. Per the SLSA spec,
// "external" means inputs another invoker could have set to reproduce the
// build — destinations, source context, Dockerfile path, build args.
func externalParameters(opts *config.KanikoOptions) map[string]interface{} {
	out := map[string]interface{}{
		"destinations": []string(opts.Destinations),
		"dockerfile":   opts.DockerfilePath,
		"context":      opts.SrcContext,
	}
	if len(opts.BuildArgs) > 0 {
		// BuildArgs is []string with entries like "KEY=value"; pass through
		// as-is to keep the attestation honest about what was supplied.
		out["buildArgs"] = []string(opts.BuildArgs)
	}
	if opts.Target != "" {
		out["target"] = opts.Target
	}
	if opts.CustomPlatform != "" {
		out["platform"] = opts.CustomPlatform
	}
	return out
}

// internalParameters captures builder-side configuration that affected the
// build but is not a "user input" in the SLSA sense — caching, reproducible
// mode, snapshot mode, etc. Recording them aids debugging without making the
// build artifact-identifying.
func internalParameters(opts *config.KanikoOptions) map[string]interface{} {
	return map[string]interface{}{
		"cache":         opts.Cache,
		"reproducible":  opts.Reproducible,
		"snapshotMode":  opts.SnapshotMode,
		"singleShot":    opts.SingleSnapshot,
		"compressedTar": opts.CompressedCaching,
	}
}

// newInvocationID returns a random 128-bit hex string used to correlate the
// attestation with build logs. Cryptographic strength is not required (this
// is an identifier, not a token), but crypto/rand keeps collisions
// vanishingly unlikely across machines and pipelines. On the extraordinarily
// unlikely event of rand failure, fall back to a time-suffixed marker so
// the field stays populated rather than aborting the build.
func newInvocationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ts-%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// normalizeSHA256 accepts either a bare hex digest or a "sha256:..." prefixed
// digest and returns the bare hex form. Validates length (64 hex chars).
func normalizeSHA256(digest string) (string, error) {
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) != 64 {
		return "", errors.Errorf("expected 64-char sha256 digest, got %d chars", len(d))
	}
	for _, c := range d {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", errors.Errorf("digest contains non-hex char %q", c)
		}
	}
	return d, nil
}
