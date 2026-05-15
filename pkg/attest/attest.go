/*
Copyright 2026 The Kaniko Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package attest produces in-toto attestations describing how a tatara build
// produced a container image. The current implementation emits SLSA
// Provenance v1.0 documents (https://slsa.dev/spec/v1.0/provenance) wrapped
// in an in-toto v1 Statement envelope.
//
// Attestations are written to disk in JSON form and are not yet uploaded to
// the registry or signed; signing/upload land in subsequent slices.
package attest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/iahsanGill/tatara/pkg/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Standard URIs from the in-toto and SLSA specifications. Hardcoded here so
// callers do not have to remember the canonical strings.
const (
	// InTotoStatementV1 is the canonical _type URI for an in-toto v1
	// Statement envelope.
	InTotoStatementV1 = "https://in-toto.io/Statement/v1"

	// SLSAProvenanceV1Predicate is the predicateType URI for SLSA Provenance
	// v1.0 predicates.
	SLSAProvenanceV1Predicate = "https://slsa.dev/provenance/v1"

	// BuildTypeTataraDockerfileV1 identifies the buildType used by tatara
	// for Dockerfile-based builds. Stable for the lifetime of the v1
	// provenance schema; bumping requires a buildType bump too.
	BuildTypeTataraDockerfileV1 = "https://github.com/iahsanGill/tatara/builds/dockerfile/v1"

	// BuilderID identifies tatara as the builder. Used as the value of
	// runDetails.builder.id in the produced predicate.
	BuilderID = "https://github.com/iahsanGill/tatara"
)

// ValidateOptions checks that ProvenanceOptions are internally consistent.
// Called from CLI flag validation so errors surface before the build runs.
func ValidateOptions(opts config.ProvenanceOptions) error {
	if opts.OutputPath == "" {
		// Nothing requested — anything is fine.
		return nil
	}
	if !filepath.IsAbs(opts.OutputPath) {
		return fmt.Errorf("--provenance-path must be an absolute path, got %q", opts.OutputPath)
	}
	return nil
}

// Generate writes a SLSA Provenance v1.0 attestation describing the build of
// image to opts.Provenance.OutputPath. When OutputPath is empty Generate is a
// no-op. Subjects are derived from opts.Destinations using the supplied
// image's digest.
//
// startedAt and finishedAt bracket the build; both are recorded in
// runDetails.metadata so verifiers can cross-check timing.
func Generate(opts *config.KanikoOptions, imageDigest string, startedAt, finishedAt time.Time) error {
	if opts.Provenance.OutputPath == "" {
		return nil
	}
	if err := ValidateOptions(opts.Provenance); err != nil {
		return errors.Wrap(err, "invalid provenance options")
	}

	stmt, err := buildStatement(opts, imageDigest, startedAt, finishedAt)
	if err != nil {
		return errors.Wrap(err, "building provenance statement")
	}
	if err := writeStatement(stmt, opts.Provenance.OutputPath); err != nil {
		return errors.Wrapf(err, "writing provenance to %s", opts.Provenance.OutputPath)
	}
	return nil
}

// writeStatement serializes stmt to outputPath as indented JSON, using a
// temp-file-plus-rename so a partially-written file never appears on disk.
func writeStatement(stmt *Statement, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return errors.Wrap(err, "creating provenance output directory")
	}
	tmp, err := os.CreateTemp(filepath.Dir(outputPath), filepath.Base(outputPath)+".tmp.*")
	if err != nil {
		return errors.Wrap(err, "creating temp provenance file")
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(stmt); err != nil {
		_ = tmp.Close()
		return errors.Wrap(err, "encoding provenance JSON")
	}
	if err := tmp.Close(); err != nil {
		return errors.Wrap(err, "closing temp provenance file")
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return errors.Wrap(err, "renaming provenance into place")
	}
	logrus.Infof("SLSA provenance written to %s (subjects=%d)", outputPath, len(stmt.Subject))
	return nil
}
