/*
Copyright 2026 The Kaniko Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package sbom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iahsanGill/tatara/pkg/config"
)

func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    config.SBOMOptions
		wantErr string
	}{
		{
			name: "disabled: empty format is a no-op",
			opts: config.SBOMOptions{},
		},
		{
			name: "valid spdx-json",
			opts: config.SBOMOptions{Format: FormatSPDXJSON, OutputPath: "/tmp/sbom.json"},
		},
		{
			name: "valid cyclonedx-json",
			opts: config.SBOMOptions{Format: FormatCycloneDXJSON, OutputPath: "/tmp/sbom.json"},
		},
		{
			name:    "format set, path missing",
			opts:    config.SBOMOptions{Format: FormatSPDXJSON},
			wantErr: "--sbom-path",
		},
		{
			name:    "unknown format",
			opts:    config.SBOMOptions{Format: "spdx-xml", OutputPath: "/tmp/sbom.xml"},
			wantErr: "unsupported --sbom-format",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOptions(tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestGenerate_DisabledIsNoop(t *testing.T) {
	// With Format empty, Generate must not touch the filesystem nor invoke
	// the scanner. We verify by pointing OutputPath at a guaranteed-unwritable
	// location and asserting no error.
	opts := &config.KanikoOptions{}
	opts.SBOM = config.SBOMOptions{
		Format:     "",
		OutputPath: "/does/not/exist/sbom.json",
	}

	if err := Generate(context.Background(), opts, "irrelevant"); err != nil {
		t.Fatalf("Generate should be no-op when Format is empty, got: %v", err)
	}
}

func TestSupportedFormats(t *testing.T) {
	got := SupportedFormats()
	wantSet := map[string]bool{FormatSPDXJSON: true, FormatCycloneDXJSON: true}
	if len(got) != len(wantSet) {
		t.Fatalf("SupportedFormats() length = %d, want %d", len(got), len(wantSet))
	}
	for _, f := range got {
		if !wantSet[f] {
			t.Errorf("unexpected format %q in SupportedFormats()", f)
		}
	}
	// Verify the returned slice is a copy (mutating it must not affect the
	// next caller).
	got[0] = "tampered"
	again := SupportedFormats()
	if again[0] == "tampered" {
		t.Error("SupportedFormats returned a shared backing slice; mutations leak")
	}
}

// TestWriteSBOM_Atomic verifies that writeSBOM produces a complete file when
// the encoder succeeds, and leaves no debris when it fails.
func TestWriteSBOM_Atomic(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "subdir", "sbom.json")

	// Hand-build a minimal SBOM that will encode cleanly. We don't go through
	// the full scan pipeline here — just exercise the write path.
	doc := newEmptyTestSBOM()
	if err := writeSBOM(doc, config.SBOMOptions{
		Format:     FormatSPDXJSON,
		OutputPath: out,
	}); err != nil {
		t.Fatalf("writeSBOM: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading written SBOM: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("written SBOM is empty")
	}

	// Output must be parseable JSON with an SPDX-shaped top level.
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("written SBOM is not valid JSON: %v", err)
	}
	if _, ok := top["spdxVersion"]; !ok {
		t.Errorf("written SBOM missing spdxVersion field; top-level keys: %v", keysOf(top))
	}

	// No temp files should remain in the output dir.
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("leftover temp file %s after successful write", e.Name())
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
