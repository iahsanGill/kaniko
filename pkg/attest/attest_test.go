/*
Copyright 2026 The Kaniko Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GoogleContainerTools/kaniko/pkg/config"
)

const fakeDigestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestValidateOptions(t *testing.T) {
	cases := []struct {
		name    string
		opts    config.ProvenanceOptions
		wantErr string
	}{
		{name: "disabled is fine", opts: config.ProvenanceOptions{}},
		{name: "absolute path is fine", opts: config.ProvenanceOptions{OutputPath: "/tmp/p.json"}},
		{name: "relative path rejected", opts: config.ProvenanceOptions{OutputPath: "p.json"}, wantErr: "absolute path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOptions(tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestGenerate_DisabledIsNoop(t *testing.T) {
	opts := &config.KanikoOptions{}
	// OutputPath empty: must be a no-op regardless of anything else.
	if err := Generate(opts, "sha256:"+fakeDigestHex, time.Now(), time.Now()); err != nil {
		t.Fatalf("Generate should be no-op when OutputPath empty, got %v", err)
	}
}

func TestGenerate_ProducesValidStatement(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sub", "provenance.json")

	opts := &config.KanikoOptions{}
	opts.Provenance.OutputPath = out
	opts.Destinations = []string{"my.registry/img:v1", "my.registry/img:latest"}
	opts.DockerfilePath = "/workspace/Dockerfile"
	opts.SrcContext = "dir:///workspace"
	opts.BuildArgs = []string{"FOO=bar"}
	opts.Target = "prod"
	opts.CustomPlatform = "linux/arm64"
	opts.Cache = true
	opts.Reproducible = true

	startedAt := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(42 * time.Second)

	if err := Generate(opts, "sha256:"+fakeDigestHex, startedAt, finishedAt); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading provenance: %v", err)
	}

	var stmt Statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		t.Fatalf("provenance is not valid JSON: %v", err)
	}

	// Envelope identity.
	if stmt.Type != InTotoStatementV1 {
		t.Errorf("Type = %q, want %q", stmt.Type, InTotoStatementV1)
	}
	if stmt.PredicateType != SLSAProvenanceV1Predicate {
		t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, SLSAProvenanceV1Predicate)
	}

	// Subjects: one per destination, each with sha256 digest.
	if len(stmt.Subject) != 2 {
		t.Fatalf("Subject count = %d, want 2 (one per destination)", len(stmt.Subject))
	}
	for i, s := range stmt.Subject {
		if s.Name != opts.Destinations[i] {
			t.Errorf("Subject[%d].Name = %q, want %q", i, s.Name, opts.Destinations[i])
		}
		if s.Digest["sha256"] != fakeDigestHex {
			t.Errorf("Subject[%d].Digest[sha256] = %q, want %q", i, s.Digest["sha256"], fakeDigestHex)
		}
	}

	// BuildDefinition.
	if stmt.Predicate.BuildDefinition.BuildType != BuildTypeKanikoDockerfileV1 {
		t.Errorf("buildType = %q, want %q", stmt.Predicate.BuildDefinition.BuildType, BuildTypeKanikoDockerfileV1)
	}
	ext := stmt.Predicate.BuildDefinition.ExternalParameters
	if got, _ := ext["dockerfile"].(string); got != opts.DockerfilePath {
		t.Errorf("externalParameters.dockerfile = %v, want %q", ext["dockerfile"], opts.DockerfilePath)
	}
	if got, _ := ext["context"].(string); got != opts.SrcContext {
		t.Errorf("externalParameters.context = %v, want %q", ext["context"], opts.SrcContext)
	}
	if _, ok := ext["buildArgs"]; !ok {
		t.Error("externalParameters missing buildArgs")
	}
	if got, _ := ext["target"].(string); got != "prod" {
		t.Errorf("externalParameters.target = %v, want prod", ext["target"])
	}

	// RunDetails.
	if stmt.Predicate.RunDetails.Builder.ID != BuilderID {
		t.Errorf("builder.id = %q, want %q", stmt.Predicate.RunDetails.Builder.ID, BuilderID)
	}
	if _, ok := stmt.Predicate.RunDetails.Builder.Version["kaniko"]; !ok {
		t.Error("builder.version missing kaniko entry")
	}
	if !stmt.Predicate.RunDetails.Metadata.StartedOn.Equal(startedAt) {
		t.Errorf("startedOn mismatch: got %v want %v", stmt.Predicate.RunDetails.Metadata.StartedOn, startedAt)
	}
	if !stmt.Predicate.RunDetails.Metadata.FinishedOn.Equal(finishedAt) {
		t.Errorf("finishedOn mismatch: got %v want %v", stmt.Predicate.RunDetails.Metadata.FinishedOn, finishedAt)
	}
	// InvocationID must be populated. We generate 16 random bytes hex-encoded,
	// so a successful invocation produces a 32-char hex string. Fallback path
	// produces a "ts-<nanos>" prefix — also non-empty, but should never be hit
	// in practice; assert format strictly so a fallback regression is caught.
	if got := stmt.Predicate.RunDetails.Metadata.InvocationID; len(got) != 32 {
		t.Errorf("invocationId %q has length %d, want 32 hex chars", got, len(got))
	}

	// No leftover temp files in the output dir.
	entries, _ := os.ReadDir(filepath.Dir(out))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("leftover temp file %s after successful write", e.Name())
		}
	}
}

func TestGenerate_NoDestinationsStillEmitsSubject(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.json")
	opts := &config.KanikoOptions{}
	opts.Provenance.OutputPath = out

	if err := Generate(opts, "sha256:"+fakeDigestHex, time.Now(), time.Now()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, _ := os.ReadFile(out)
	var stmt Statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(stmt.Subject) != 1 || stmt.Subject[0].Name != "image" {
		t.Errorf("want one subject named 'image', got %+v", stmt.Subject)
	}
}

func TestNormalizeSHA256(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"sha256:" + fakeDigestHex, fakeDigestHex, false},
		{fakeDigestHex, fakeDigestHex, false},
		{"sha256:" + strings.Repeat("g", 64), "", true}, // non-hex
		{"sha256:short", "", true},                      // wrong length
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeSHA256(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeSHA256(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeSHA256(%q) unexpected err: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("normalizeSHA256(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
