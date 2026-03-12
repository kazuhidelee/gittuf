// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package readaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/gittuf/gittuf/pkg/gitinterface"
)

var (
	ErrNoKeyMetadataForPrincipal = errors.New("no key metadata for principal")
	ErrIncorrectNumberOfBlobs    = errors.New("incorrect number of blobs")
)

// LoadMetadata loads the principal key metadata for the given principal from
// the temporary storage area.
func LoadMetadata(repo *gitinterface.Repository, principalID string) (*PrincipalKeys, error) {
	targetRefID := PrincipalKeyRefPrefix + principalID

	// First, check if the given ref exists
	commitID, err := repo.GetReference(targetRefID)
	if errors.Is(err, gitinterface.ErrReferenceNotFound) {
		return nil, ErrNoKeyMetadataForPrincipal
	} else if err != nil {
		return nil, err
	}

	// If the given ref exists, proceed to load the commit
	commitTreeID, err := repo.GetCommitTreeID(commitID)
	if err != nil {
		return nil, err
	}

	treeItems, err := repo.GetTreeItems(commitTreeID)
	if err != nil {
		return nil, err
	}

	principalKeyMetadata := &PrincipalKeyMetadata{}

	if len(treeItems) > 1 {
		return nil, ErrIncorrectNumberOfBlobs
	}

	for name, blobID := range treeItems {
		contents, err := repo.ReadBlob(blobID)
		if err != nil {
			return nil, err
		}

		env := &sslibdsse.Envelope{}
		if err := json.Unmarshal(contents, env); err != nil {
			return nil, err
		}

		principalKeyMetadata.PrincipalID = name
		principalKeyMetadata.MetadataEnvelope = env
	}

	principalKeys := PrincipalKeys{}

	envPayloadBytes, err := principalKeyMetadata.MetadataEnvelope.DecodeB64Payload()
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(envPayloadBytes, &principalKeys); err != nil {
		return nil, err
	}

	principalKeys.PrincipalID = principalID
	return &principalKeys, nil
}

// UpdateMetadata writes the principal key metadata for the given principal into
// the temporary storage area. It ensures that the old copy of the metadata is
// destroyed and removed from the repository by the garbage collector.
func (p *PrincipalKeyMetadata) UpdateMetadata(repo *gitinterface.Repository, principalID string, gc bool) error {
	targetRefID := PrincipalKeyRefPrefix + principalID

	slog.Debug(fmt.Sprintf("Updating metadata for principal '%s' in ref '%s'", principalID, targetRefID))
	// First, check if the given ref exists
	existingCommit, err := repo.GetReference(targetRefID)
	if err != nil {
		if !errors.Is(err, gitinterface.ErrReferenceNotFound) {
			return err
		}
	}

	// Now, build the tree for the commit
	//allTreeEntries := []gitinterface.TreeEntry{}
	treeEntry, err := p.WriteTree(repo)
	if err != nil {
		return err
	}

	err = repo.SetReference(targetRefID, gitinterface.ZeroHash)
	if err != nil {
		return err
	}

	commitMessage := fmt.Sprintf("Key metadata for principal '%s'", principalID)

	_, err = repo.Commit(treeEntry, targetRefID, commitMessage, true)
	if err != nil {
		return err
	}

	// If the ref did exist before we updated it here, we need to overwrite it
	// and ensure that the previous commit the ref pointed to is garbage
	// collected
	if gc && !existingCommit.Equal(gitinterface.ZeroHash) {
		slog.Debug(fmt.Sprintf("Garbage collecting to remove old metadata..."))
		// Delete the existing commit
		err = repo.InvokeGarbageCollector(true)
		if err != nil {
			return err
		}
	}

	return nil
}
