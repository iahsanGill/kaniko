/*
Copyright 2026 The Kaniko Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package sbom

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// newEmptyTestSBOM returns a syntactically valid but empty SBOM document
// suitable for exercising the encoder/writer paths without running a real
// scan. Tests must not depend on its semantic content beyond "encodes cleanly".
func newEmptyTestSBOM() *sbom.SBOM {
	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
		Relationships: nil,
		Source: source.Description{
			Name: "test",
		},
		Descriptor: sbom.Descriptor{
			Name:    "kaniko",
			Version: "test",
		},
	}
}

// Ensure imports stay live when only used inside test helpers.
var _ = artifact.ID("")
