package registry

import (
	"fmt"
	"regexp"

	"github.com/opencontainers/go-digest"
)

type referenceType string

const (
	referenceTypeManifest = "Manifest"
	referenceTypeBlob     = "Blob"
)

// Package is used to parse components from requests which comform with the OCI distribution spec.
// https://github.com/opencontainers/distribution-spec/blob/main/spec.md
// /v2/<name>/manifests/<reference>
// /v2/<name>/blobs/<reference>

var (
	nameRegex           = regexp.MustCompile(`([a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*)`)
	tagRegex            = regexp.MustCompile(`([a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})`)
	manifestRegexTag    = regexp.MustCompile(`/v2/` + nameRegex.String() + `/manifests/` + tagRegex.String() + `$`)
	manifestRegexDigest = regexp.MustCompile(`/v2/` + nameRegex.String() + `/manifests/(.*)`)
	blobsRegexDigest    = regexp.MustCompile(`/v2/` + nameRegex.String() + `/blobs/(.*)`)
)

func parsePathComponents(registry, path string) (string, digest.Digest, referenceType, error) {
	comps := manifestRegexTag.FindStringSubmatch(path)
	if len(comps) == 6 {
		if registry == "" {
			return "", "", "", fmt.Errorf("registry parameter needs to be set for tag references")
		}
		ref := fmt.Sprintf("%s/%s:%s", registry, comps[1], comps[5])
		return ref, "", referenceTypeManifest, nil
	}
	comps = manifestRegexDigest.FindStringSubmatch(path)
	if len(comps) == 6 {
		return "", digest.Digest(comps[5]), referenceTypeManifest, nil
	}
	comps = blobsRegexDigest.FindStringSubmatch(path)
	if len(comps) == 6 {
		return "", digest.Digest(comps[5]), referenceTypeBlob, nil
	}
	return "", "", "", fmt.Errorf("distribution path could not be parsed")
}
