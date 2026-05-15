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
	"context"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/iahsanGill/tatara/pkg/util"
	"github.com/iahsanGill/tatara/pkg/version"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	// modernc.org/sqlite is a pure-Go sqlite driver, registered as "sqlite".
	// syft's RPM cataloger requires a "sqlite" driver to read the BerkeleyDB
	// or sqlite-backed RPM databases used by Fedora/RHEL/CentOS images.
	// Without this blank import RPM cataloging silently fails and those
	// images would yield empty SBOMs.
	_ "modernc.org/sqlite"
)

// rootScanPath is the filesystem location syft scans. After DoBuild finishes
// and before DoPush starts, the kaniko container's root IS the built image's
// filesystem, so scanning "/" is equivalent to scanning the final image.
const rootScanPath = "/"

// scanRootfs walks the kaniko root filesystem and returns a populated SBOM
// document. imageRef is informational — it is recorded as the scan subject
// in the SBOM metadata so downstream tools know which image this SBOM
// describes.
func scanRootfs(ctx context.Context, imageRef string) (*sbom.SBOM, error) {
	excludePaths := buildExcludePaths()
	logrus.Debugf("SBOM scan excluding %d paths from %s", len(excludePaths), rootScanPath)

	src, err := directorysource.New(directorysource.Config{
		Path: rootScanPath,
		Base: rootScanPath,
		Alias: source.Alias{
			Name: imageRef,
		},
		Exclude: source.ExcludeConfig{
			Paths: excludePaths,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "creating syft directory source")
	}
	defer func() {
		if cerr := src.Close(); cerr != nil {
			logrus.Debugf("closing syft source: %v", cerr)
		}
	}()

	cfg := syft.DefaultCreateSBOMConfig()
	result, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, errors.Wrap(err, "syft.CreateSBOM")
	}

	// Override the SBOM's tool attribution so downstream consumers can tell
	// this SBOM was emitted by tatara (which calls syft under the hood)
	// rather than syft being invoked directly. The syft version stays
	// visible inside the descriptor's Configuration block.
	result.Descriptor = sbom.Descriptor{
		Name:    "tatara",
		Version: version.Version(),
		Configuration: map[string]string{
			"engine":         "syft",
			"engine.version": result.Descriptor.Version,
		},
	}

	logrus.Infof("SBOM scan found %d packages in image %s", result.Artifacts.Packages.PackageCount(), imageRef)
	return result, nil
}

// buildExcludePaths returns syft-compatible exclusion globs derived from
// kaniko's IgnoreList. Those entries are exactly what kaniko already
// considers "not part of the user's image" — kaniko's own working dir, host
// kernel mounts, runtime tmpfs, etc.
//
// syft's doublestar matcher requires patterns to start with "./", "*/", or
// "**/". Kaniko's IgnoreList uses absolute paths (/kaniko, /proc, ...) so we
// translate the leading "/" to "./" relative to the scan root.
func buildExcludePaths() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(glob string) {
		if _, ok := seen[glob]; ok {
			return
		}
		seen[glob] = struct{}{}
		out = append(out, glob)
	}
	for _, e := range util.IgnoreList() {
		glob := toSyftGlob(e.Path)
		if glob == "" {
			continue
		}
		add(glob)
		// PrefixMatchOnly entries (e.g. /tmp/apt-key-gpghome*) need a second
		// glob that catches descendants.
		if e.PrefixMatchOnly {
			add(glob + "/**")
		}
	}
	return out
}

// toSyftGlob converts a kaniko-style absolute filesystem path ("/kaniko")
// into a syft-compatible doublestar exclusion glob ("./kaniko"). Empty input
// and the bare scan root are rejected (excluding "/" would skip everything).
func toSyftGlob(path string) string {
	if path == "" || path == "/" {
		return ""
	}
	if len(path) > 0 && path[0] == '/' {
		return "." + path
	}
	// Relative paths get the "./" prefix.
	return "./" + path
}
