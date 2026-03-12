// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/readaccess"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	sslibed "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/encrypterdecrypter"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/gittuf/gittuf/pkg/gitinterface"
)

var (
	ErrNoEncrypters = errors.New("no encrypters provided")
	ErrNoDecrypters = errors.New("no decrypters provided")
)

// EncryptState encrypts and commits the repository files as per the read access
// control policy specified in the repository, under the principal specified by
// the signer. Any paths that are specified as protected and currently mutated
// are encrypted, added to the repository as blobs, and committed as a new
// commit under the specified ref.
func (r *Repository) EncryptState(ctx context.Context, refName, commitMessage string, signer sslibdsse.SignerVerifier) error {
	if signer == nil {
		return sslibdsse.ErrNoSigners
	}

	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyRef)
	if err != nil {
		return err
	}

	var signingPrincipal tuf.Principal
	for _, principal := range state.GetAllPrincipals() {
		for _, key := range principal.Keys() {
			if key.KeyID == keyID {
				slog.Debug(fmt.Sprintf("Matched supplied key with ID '%s' to principal with ID '%s'", keyID, principal.ID()))
				signingPrincipal = principal
				break
			}
		}
	}

	if signingPrincipal == nil {
		return tuf.ErrPrincipalNotFound
	}

	paths, err := r.r.GetFilePathsChangedSinceLastCommit(true)
	if err != nil {
		return err
	}

	pathsToAuthorizedPrincipals := make(map[string][]tuf.Principal)

	for _, path := range paths {
		slog.Debug(fmt.Sprintf("Checking if path '%s' must be encrypted...", path))
		principalsForPath, err := state.DetermineIfPathMustBeEncrypted(fmt.Sprintf("%s:%s", policy.FileRuleScheme, path), gitinterface.ZeroHash, true)
		if err != nil {
			return err
		}

		if principalsForPath != nil {
			slog.Debug("Path must be encrypted")
			pathsToAuthorizedPrincipals[path] = principalsForPath
		}
	}

	newCommitHash, err := readaccess.EncryptNewState(ctx, r.r, refName, commitMessage, pathsToAuthorizedPrincipals, signer)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Successfully created new commit with hash '%s'!", newCommitHash.String()))
	fmt.Print(newCommitHash.String())
	return nil
}

// DecryptState decrypts the repository files at the specified commit that the
// specified principal has access to according to the read access control
// policy. There must be at least one private key defined for the principal
// currently available on the system for decryption to succeed.
func (r *Repository) DecryptState(ctx context.Context, commitHash gitinterface.Hash, decrypter sslibed.Decrypter) error {
	if decrypter == nil {
		return ErrNoDecrypters
	}

	keyID, err := decrypter.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyRef)
	if err != nil {
		return err
	}

	var selectedPrincipal tuf.Principal
	for _, principal := range state.GetAllPrincipals() {
		for _, key := range principal.Keys() {
			if key.KeyID == keyID {
				slog.Debug("Matched supplied key with ID '%s' to principal with ID '%s'", keyID, principal.ID())
				selectedPrincipal = principal
				break
			}
		}
	}

	if selectedPrincipal == nil {
		return tuf.ErrPrincipalNotFound
	}

	return readaccess.DecryptState(r.r, commitHash, selectedPrincipal.ID(), decrypter)
}
