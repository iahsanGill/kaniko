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

package attest

import "time"

// Statement is the in-toto v1 Statement envelope. Type and PredicateType are
// fixed URIs; Subject names the artifacts the attestation is about; Predicate
// carries the schema-specific claim — here, a SLSA Provenance v1.0 document.
//
// Reference: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
type Statement struct {
	Type          string              `json:"_type"`
	Subject       []Subject           `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     ProvenancePredicate `json:"predicate"`
}

// Subject identifies an artifact the attestation refers to. For container
// images Name is the image reference (registry/repo:tag) and Digest is keyed
// by hash algorithm (typically "sha256").
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ProvenancePredicate is the SLSA Provenance v1.0 predicate.
//
// Reference: https://slsa.dev/spec/v1.0/provenance
type ProvenancePredicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition fully describes the inputs and process that produced the
// artifact. BuildType is a stable URI identifying the build schema;
// ExternalParameters captures user-supplied build inputs (those a different
// user could have provided to get the same artifact); InternalParameters
// captures builder defaults; ResolvedDependencies lists materials whose
// digests are known.
type BuildDefinition struct {
	BuildType            string                 `json:"buildType"`
	ExternalParameters   map[string]interface{} `json:"externalParameters"`
	InternalParameters   map[string]interface{} `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor   `json:"resolvedDependencies,omitempty"`
}

// ResourceDescriptor describes an input or dependency. At least one of Name,
// URI, or Digest must be set.
type ResourceDescriptor struct {
	Name   string            `json:"name,omitempty"`
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// RunDetails records who/what ran the build and when.
type RunDetails struct {
	Builder  Builder  `json:"builder"`
	Metadata Metadata `json:"metadata"`
}

// Builder identifies the builder. ID is a stable URI; Version is a free-form
// map (commonly contains the builder's own name+version).
type Builder struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

// Metadata records timing for the build run.
type Metadata struct {
	InvocationID string    `json:"invocationId,omitempty"`
	StartedOn    time.Time `json:"startedOn"`
	FinishedOn   time.Time `json:"finishedOn"`
}
