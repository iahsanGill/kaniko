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

// Package sbom generates Software Bill of Materials (SBOM) artifacts for
// images built by kaniko.
//
// The SBOM is produced after DoBuild completes and before DoPush runs, by
// scanning the live root filesystem of the kaniko container — which at that
// moment is identical to the final image's root filesystem — with the syft
// library. Paths kaniko itself manages (kaniko's working dir, /proc, /sys,
// /dev, /run, /tmp, etc.) are excluded via kaniko's existing IgnoreList so
// they do not pollute the SBOM.
//
// SBOM generation is gated by config.SBOMOptions.Format. When Format is the
// empty string, Generate is a no-op. When set, OutputPath must also be set.
package sbom

import (
	"context"
	"fmt"

	"github.com/iahsanGill/tatara/pkg/config"
	"github.com/pkg/errors"
)

// Supported SBOM output formats. Values match the canonical syft format
// identifiers so users with prior syft experience can transfer expectations.
const (
	FormatSPDXJSON      = "spdx-json"
	FormatCycloneDXJSON = "cyclonedx-json"
)

// supportedFormats lists every accepted value of SBOMOptions.Format. Useful
// for flag validation and help text.
var supportedFormats = []string{FormatSPDXJSON, FormatCycloneDXJSON}

// SupportedFormats returns the SBOM formats kaniko knows how to emit.
func SupportedFormats() []string {
	out := make([]string, len(supportedFormats))
	copy(out, supportedFormats)
	return out
}

// ValidateOptions checks that SBOMOptions are internally consistent. It is
// called from CLI flag validation so errors surface before the build runs.
func ValidateOptions(opts config.SBOMOptions) error {
	if opts.Format == "" {
		// No SBOM requested — anything is fine.
		return nil
	}
	switch opts.Format {
	case FormatSPDXJSON, FormatCycloneDXJSON:
	default:
		return fmt.Errorf("unsupported --sbom-format %q (supported: %v)", opts.Format, supportedFormats)
	}
	if opts.OutputPath == "" {
		return fmt.Errorf("--sbom-format requires --sbom-path")
	}
	return nil
}

// Generate runs the SBOM pipeline end-to-end. It is a no-op when SBOM is not
// configured. imageRef is recorded as the scan subject in the SBOM metadata;
// it should be the user's final image destination tag (any one of them is
// fine when there are multiple destinations).
func Generate(ctx context.Context, opts *config.KanikoOptions, imageRef string) error {
	if opts.SBOM.Format == "" {
		return nil
	}
	if err := ValidateOptions(opts.SBOM); err != nil {
		return errors.Wrap(err, "invalid SBOM options")
	}

	sbomDoc, err := scanRootfs(ctx, imageRef)
	if err != nil {
		return errors.Wrap(err, "scanning root filesystem for SBOM")
	}

	if err := writeSBOM(sbomDoc, opts.SBOM); err != nil {
		return errors.Wrapf(err, "writing SBOM to %s", opts.SBOM.OutputPath)
	}
	return nil
}
