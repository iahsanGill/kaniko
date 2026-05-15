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

package sbom

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/iahsanGill/tatara/pkg/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// writeSBOM encodes doc in the configured format and writes it atomically to
// opts.OutputPath. Atomic write (temp file + rename) prevents partial files
// on the disk if the encoder fails partway through.
func writeSBOM(doc *sbom.SBOM, opts config.SBOMOptions) error {
	if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o755); err != nil {
		return errors.Wrap(err, "creating SBOM output directory")
	}

	tmp, err := os.CreateTemp(filepath.Dir(opts.OutputPath), filepath.Base(opts.OutputPath)+".tmp.*")
	if err != nil {
		return errors.Wrap(err, "creating temp SBOM file")
	}
	tmpPath := tmp.Name()
	defer func() {
		// If we never renamed, remove the temp file so we don't leave debris.
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := encode(tmp, doc, opts.Format); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return errors.Wrap(err, "closing temp SBOM file")
	}

	if err := os.Rename(tmpPath, opts.OutputPath); err != nil {
		return errors.Wrap(err, "renaming SBOM into place")
	}
	logrus.Infof("SBOM written to %s (format=%s)", opts.OutputPath, opts.Format)
	return nil
}

// encode picks the right syft encoder for the requested format and writes
// the SBOM document to w.
func encode(w io.Writer, doc *sbom.SBOM, format string) error {
	switch format {
	case FormatSPDXJSON:
		enc, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
		if err != nil {
			return errors.Wrap(err, "creating SPDX JSON encoder")
		}
		if err := enc.Encode(w, *doc); err != nil {
			return errors.Wrap(err, "encoding SBOM as SPDX JSON")
		}
		return nil
	case FormatCycloneDXJSON:
		enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		if err != nil {
			return errors.Wrap(err, "creating CycloneDX JSON encoder")
		}
		if err := enc.Encode(w, *doc); err != nil {
			return errors.Wrap(err, "encoding SBOM as CycloneDX JSON")
		}
		return nil
	default:
		// Should be caught by ValidateOptions before we ever reach here.
		return fmt.Errorf("unsupported SBOM format %q", format)
	}
}
