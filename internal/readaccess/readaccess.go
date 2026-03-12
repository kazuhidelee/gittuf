// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package readaccess

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/gittuf/gittuf/internal/signerverifier/dsse"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	sslibed "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/encrypterdecrypter"
	sslibeda "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/encrypterdecrypter/asymmetric"
	sslibeds "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/encrypterdecrypter/symmetric"
	"github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/signerverifier"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"golang.org/x/crypto/ssh"
)

const (
	PrincipalKeyRefPrefix = "refs/arcanum/keydata/"
)

var (
	ErrMetadataDoesNotExistForState = errors.New("state key metadata does not exist for principal for state")
	ErrMetadataDoesNotExistForPath  = errors.New("path key with the specified key ID does not exist for path")
)

// PrincipalKeyMetadata is the DSSE envelope that contains all key metadata for
// a principal
type PrincipalKeyMetadata struct {
	PrincipalID      string
	MetadataEnvelope *sslibdsse.Envelope
}

type PrincipalKeys struct {
	Metadata *PrincipalKeyMetadata

	PrincipalID string                `json:"principalID"`
	Keys        map[string]ObjectKeys `json:"objectKeys"`
}

type ObjectKeys struct {
	ID   gitinterface.Hash `json:"id"`
	Keys map[string][]byte `json:"encryptedKeys"`
}

//// PrincipalKeys represents the full set of key metadata required to access any
//// non-world-readable data for a principal.
//type PrincipalKeys struct {
//	Metadata *PrincipalKeyMetadata
//
//	PrincipalID string               `json:"principalID"`
//	States      map[string]StateKeys `json:"states"`
//}
//
//// StateKeys represents the set of key metadata for a specific state in the
//// repository
//type StateKeys struct {
//	ID    gitinterface.Hash `json:"stateID"`
//	Paths []PathKeys        `json:"paths"`
//}
//
//// PathKeys represents the set of key metadata for a specific path in the
//// repository
//type PathKeys struct {
//	ID            string            `json:"pathID"`
//	EncryptedKeys map[string][]byte `json:"encryptedKeys"`
//}

// WriteTree writes the DSSE envelope to the repository and returns the tree
// containing the written blob
func (p *PrincipalKeyMetadata) WriteTree(repo *gitinterface.Repository) (gitinterface.Hash, error) {
	allTreeEntries := []gitinterface.TreeEntry{}

	env := p.MetadataEnvelope
	slog.Debug(fmt.Sprintf("State envelope: %+v", env))

	envContents, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	blobID, err := repo.WriteBlob(envContents)
	if err != nil {
		return nil, err
	}

	allTreeEntries = append(allTreeEntries, gitinterface.NewEntryBlob(p.PrincipalID+".json", blobID))

	treeBuilder := gitinterface.NewTreeBuilder(repo)
	return treeBuilder.WriteTreeFromEntries(allTreeEntries)
}

// EncryptNewState encrypts the given paths with their specified encryption
// keys, and writes the changes to the repository as a new commit, as well
// as updates the metadata for the principal in the temporary storage area.
func EncryptNewState(ctx context.Context, repo *gitinterface.Repository, ref, commitMessage string, pathsToAuthorizedPrincipals map[string][]tuf.Principal, signer sslibdsse.SignerVerifier) (gitinterface.Hash, error) {
	// For this method, we need to determine if the files/directories are
	// already present in the repository as encrypted blobs, unencrypted blobs,
	// or have never been committed to the repository. For the files that have
	// never been written, we must read them directly from the filesystem
	// instead of querying the repository for information about them.
	allTreeEntries := []gitinterface.TreeEntry{}
	treeBuilder := gitinterface.NewTreeBuilder(repo)

	// Assemble flat slices of paths and principal key mappings
	allPaths := []string{}
	newPrincipalKeys := make(map[string]PrincipalKeys)
	for path, principal := range pathsToAuthorizedPrincipals {
		// Collate all paths into a slice
		allPaths = append(allPaths, path)
		// Iterate through all principals
		for _, principal := range principal {
			// Filter through duplicates
			if _, seen := newPrincipalKeys[principal.ID()]; !seen {
				// If we haven't seen this principal before, attempt to load
				// the existing keys for this principal
				existingPrincipalKeys, err := LoadMetadata(repo, principal.ID())
				if errors.Is(err, ErrNoKeyMetadataForPrincipal) {
					// The keys do not exist, create a new metadata entry for
					// the person
					existingPrincipalKeys = &PrincipalKeys{}
				} else if err != nil {
					return nil, err
				}
				// Set the principal key set for the principal
				newPrincipalKeys[principal.ID()] = *existingPrincipalKeys
			}
		}
	}

	//// In addition, create a new principal to state key mapping
	//newObjectKeys := map[string]ObjectKeys{}

	// Derive symmetric keys for all paths to encrypt
	derivedKeys, err := DeriveNewKeys(allPaths)
	if err != nil {
		return nil, err
	}

	// Now, iterate over every path and symmetric key to use for said path
	for path, key := range derivedKeys {
		slog.Debug(fmt.Sprintf("Encrypting path '%s'...", path))
		sslKey, err := sslibeds.LoadSymmetricKey(key, sslibeds.AES)
		if err != nil {
			return nil, err
		}

		slog.Debug("Loading encrypterdecrypter...")
		encrypterDecrypter, err := sslibeds.NewAESEncrypterDecrypterFromSSLibSymmetricKey(sslKey, sslibeds.GCM)
		if err != nil {
			return nil, err
		}

		file, err := os.Open(path)
		if err != nil {
			continue
			//return nil, err
		}

		fileInfo, err := file.Stat()
		if err != nil {
			return nil, err
		}

		fileBytes := make([]byte, fileInfo.Size())
		_, err = file.Read(fileBytes)
		if err != nil {
			return nil, err
		}

		slog.Debug("Encrypting...")
		encryptedBytes, err := encrypterDecrypter.Encrypt(fileBytes)
		if err != nil {
			return nil, err
		}

		encryptedBlobID, err := repo.WriteBlob(encryptedBytes)
		if err != nil {
			return nil, err
		}
		slog.Debug(fmt.Sprintf("Successfully wrote encrypted file '%s with resulting hash '%s'.", path, encryptedBlobID))

		// Add the new blob to the set of tree entries to write
		allTreeEntries = append(allTreeEntries, gitinterface.NewEntryBlob(path, encryptedBlobID))

		// Iterate through all principals authorized to access the current path
		for _, principal := range pathsToAuthorizedPrincipals[path] {
			//// Locate the current principal state keys
			//currentPrincipalObjectKeys := newObjectKeys[principal.ID()]

			// Create a new path key entry
			objectKeys := ObjectKeys{ID: encryptedBlobID}

			// Now, create a mapping of key IDs to encrypted keys
			encryptedKeys := make(map[string][]byte)

			// Iterate through all public keys of the principal authorized to access the current path
			for _, principalKey := range principal.Keys() {
				// FIXME: Unify key structs somehow
				decodedBytes, err := base64.StdEncoding.DecodeString(principalKey.KeyVal.Public)
				if err != nil {
					return nil, err
				}
				parsedSSHKey, err := ParseSSHPublicKey(decodedBytes)
				if err != nil {
					return nil, err
				}
				convertedKey := &signerverifier.SSLibKey{
					KeyID:  principalKey.KeyID,
					Scheme: principalKey.Scheme,
					KeyVal: signerverifier.KeyVal{
						Public: string(parsedSSHKey),
					},
					KeyType:             principalKey.KeyType,
					KeyIDHashAlgorithms: principalKey.KeyIDHashAlgorithms,
				}

				slog.Debug(fmt.Sprintf("Public key data is '%s'", convertedKey))
				// Create an encrypter with the principal's public key
				principalKeyEncrypter, err := sslibeda.NewRSAEncrypterDecrypterFromSSLibKey(convertedKey)
				if err != nil {
					return nil, err
				}

				// Encrypt the symmetric key with the principal's public key
				encryptedKey, err := principalKeyEncrypter.Encrypt(key)
				if err != nil {
					return nil, err
				}

				// Store the encrypted symmetric key in the entry for the
				// principal
				encryptedKeys[principalKey.KeyID] = encryptedKey
			}

			objectKeys.Keys = encryptedKeys

			//slog.Debug(fmt.Sprintf("New path keyset is '%s' for principal with ID '%s'", encryptedKeys, principal.ID()))
			//pathKeys.EncryptedKeys = encryptedKeys
			//currentPrincipalStateKeys.Paths = append(currentPrincipalStateKeys.Paths, pathKeys)
			//newStateKeys[principal.ID()] = currentPrincipalStateKeys
			//slog.Debug(fmt.Sprintf("New current principal state keyset is '%s' for principal with ID '%s'", currentPrincipalStateKeys, principal.ID()))

			//fmt.Printf("Object keys: '%s'\n\n\n", objectKeys)
			existingObjectKeys := newPrincipalKeys[principal.ID()].Keys
			if existingObjectKeys == nil {
				existingObjectKeys = make(map[string]ObjectKeys)
			}
			existingObjectKeys[encryptedBlobID.String()] = objectKeys

			principalKeys := newPrincipalKeys[principal.ID()]
			principalKeys.Keys = existingObjectKeys
			newPrincipalKeys[principal.ID()] = principalKeys
		}
	}

	// Write the root tree
	rootTreeID, err := treeBuilder.WriteTreeFromEntries(allTreeEntries)
	if err != nil {
		return nil, err
	}

	// Commit the new commit to the repository
	newCommitHash, err := repo.Commit(rootTreeID, ref, commitMessage, false)
	if err != nil {
		return nil, err
	}

	//// Force an update of the target ref
	//err = repo.SetReference(ref, newCommitHash)
	//if err != nil {
	//	return nil, err
	//}

	//// Now, update the state keys for each principal with the commit ID and
	//// add the state keys to the principal keys
	//for principal, currentPrincipalKeySet := range newPrincipalKeys {
	//	//currentPrincipalStateSet := newPrincipalKeys[principal].States
	//	//
	//	//if currentPrincipalStateSet == nil {
	//	//	currentPrincipalStateSet = make(map[string]StateKeys)
	//	//}
	//	//
	//	//currentPrincipalStateSet[newCommitHash.String()] = newStateKeyset
	//	//currentPrincipalKeySet.States = currentPrincipalStateSet
	//
	//	newPrincipalKeys[principal] = currentPrincipalKeySet
	//}

	slog.Debug("Updating principal key metadata...")
	for principal, principalKeys := range newPrincipalKeys {
		slog.Debug(fmt.Sprintf("Updating principal key metadata for principal with ID '%s'...", principal))
		updatedPrincipalKeyMetadata := PrincipalKeyMetadata{
			PrincipalID: principal,
		}

		slog.Debug(fmt.Sprintf("Signing new principal key metadata '%s' for principal with ID '%s'...", principalKeys, principal))
		env, err := dsse.CreateEnvelope(principalKeys)
		if err != nil {
			return nil, err
		}

		env, err = dsse.SignEnvelope(ctx, env, signer)
		if err != nil {
			return nil, err
		}

		updatedPrincipalKeyMetadata.MetadataEnvelope = env
		slog.Debug(fmt.Sprintf("New principal key metadata is '%s' for principal with ID '%s'", updatedPrincipalKeyMetadata, principal))
		err = updatedPrincipalKeyMetadata.UpdateMetadata(repo, principal, false)
		if err != nil {
			return nil, err
		}
	}
	return newCommitHash, nil
}

// DecryptState decrypts the given commit with the keys applicable for the given
// principal, and writes the changes to disk, but does not commit them to the
// repository.
func DecryptState(repo *gitinterface.Repository, commitHash gitinterface.Hash, principalID string, decrypter sslibed.Decrypter) error {
	// First, attempt to load the principal key metadata for the principal
	// identified by the decrypter
	principalKeys, err := LoadMetadata(repo, principalID)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("%s", principalKeys.Keys))
	//// Now, check if we have the keys for the requested state
	//stateData, exists := principalKeys.States[commitHash.String()]
	//if !exists {
	//	return ErrMetadataDoesNotExistForState
	//}

	treeID, err := repo.GetCommitTreeID(commitHash)
	if err != nil {
		return err
	}

	decrypterKeyID, err := decrypter.KeyID()
	if err != nil {
		return err
	}

	// For each path in the commit, decrypt the blob (if it is encrypted, and we
	// have the necessary keys) and write to disk

	paths, err := repo.GetFilePathsChangedByCommit(commitHash)
	if err != nil {
		return err
	}

	for _, path := range paths {
		objectID, err := repo.GetPathIDInTree(path, treeID)
		if err != nil {
			return err
		}

		blobBytes, err := repo.ReadBlob(objectID)
		if err != nil {
			return err
		}

		objectKeys, exists := principalKeys.Keys[objectID.String()]
		//selectedKey, exists := principalKeys.EncryptedKeys[decrypterKeyID]
		if !exists {
			//return ErrMetadataDoesNotExistForPath
			slog.Debug(fmt.Sprintf("No metadata found for path '%s' with object ID '%s'", path, objectID))
		}

		key, exists := objectKeys.Keys[decrypterKeyID]
		if !exists {
			slog.Debug(fmt.Sprintf("No key found for path '%s' with object ID '%s', and key with ID '%s'", path, objectID, decrypterKeyID))
		}

		decryptedSymmetricKey, err := decrypter.Decrypt(key)
		if err != nil {
			return err
		}

		symmetricKey, err := sslibeds.LoadSymmetricKey(decryptedSymmetricKey, sslibeds.AES)
		if err != nil {
			return err
		}

		encrypterDecrypter, err := sslibeds.NewAESEncrypterDecrypterFromSSLibSymmetricKey(symmetricKey, sslibeds.GCM)
		if err != nil {
			return err
		}

		_, err = encrypterDecrypter.Decrypt(blobBytes)
		if err != nil {
			return err
		}

		//decryptedBlobBytes, err := encrypterDecrypter.Decrypt(blobBytes)
		//if err != nil {
		//	return err
		//}
		//
		//absPath, err := filepath.Abs(path)
		//if err != nil {
		//	return err
		//}
		//
		//err = os.WriteFile(absPath, decryptedBlobBytes, 0600)
		//if err != nil {
		//	return err
		//}
	}

	slog.Debug(fmt.Sprintf("Successfully decrypted commit with hash '%s'", commitHash))
	return nil
}

// DeriveNewKeys derives symmetric keys for the given paths, where each path
// specified has its own key.
func DeriveNewKeys(pathsToEncrypt []string) (map[string][]byte, error) {
	keyMapping := make(map[string][]byte, len(pathsToEncrypt))

	for _, pathName := range pathsToEncrypt {
		key, err := generateGCMKey()
		if err != nil {
			return nil, err
		}

		keyMapping[pathName] = key
	}

	return keyMapping, nil
}

//// encryptData encrypts the supplied data with the given key under AES-GCM-128
//func encryptData(data, key []byte) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	gcm, err := cipher.NewGCM(block)
//	if err != nil {
//		return nil, err
//	}
//
//	nonce := make([]byte, gcm.NonceSize())
//	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
//		return nil, err
//	}
//
//	ciphertext := gcm.Seal(nonce, nonce, data, nil)
//	return ciphertext, nil
//}
//
//// decryptData decrypts the supplied data with the given key under AES-GCM-128
//func decryptData(data, key []byte) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	gcm, err := cipher.NewGCM(block)
//	if err != nil {
//		return nil, err
//	}
//
//	nonceSize := gcm.NonceSize()
//	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
//
//	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
//	if err != nil {
//		return nil, err
//	}
//
//	return plaintext, nil
//}

// generateGCMKey generates a random 128-bit symmetric key suitable for use in
// AES-GCM-256
func generateGCMKey() ([]byte, error) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}

// ParseSSHPublicKey parses the SSH2 wire format into a PEM-encoded format,
// suitable for creating an encrypterdecrypter from.
// See https://gist.github.com/jordan-wright/a2d87797912922d5133dc4d0b90f62f3.
func ParseSSHPublicKey(sshPubBytes []byte) ([]byte, error) {
	// Now we can convert it back to PEM format
	// Remember: if you're reading the public key from a file, you probably
	// want ssh.ParseAuthorizedKey.
	parsed, err := ssh.ParsePublicKey(sshPubBytes)
	if err != nil {
		return nil, err
	}
	// To get back to an *rsa.PublicKey, we need to first upgrade to the
	// ssh.CryptoPublicKey interface
	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)

	// Then, we can call CryptoPublicKey() to get the actual crypto.PublicKey
	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	// Finally, we can convert back to an *rsa.PublicKey
	pub := pubCrypto.(*rsa.PublicKey)

	// After this, it's encoding to PEM - same as always
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	})

	return encoded, nil
}

// ParseSSHPrivateKey parses the SSH2 wire format into a PEM-encoded format,
// suitable for creating an encrypterdecrypter from.
// See https://gist.github.com/jordan-wright/a2d87797912922d5133dc4d0b90f62f3.
func ParseSSHPrivateKey(sshPubBytes []byte) ([]byte, error) {
	// Now we can convert it back to PEM format
	// Remember: if you're reading the public key from a file, you probably
	// want ssh.ParseAuthorizedKey.
	fmt.Println(string(sshPubBytes))
	parsed, err := ssh.ParsePrivateKey(sshPubBytes)
	if err != nil {
		return nil, err
	}
	// To get back to an *rsa.PublicKey, we need to first upgrade to the
	// ssh.CryptoPublicKey interface
	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)

	// Then, we can call CryptoPublicKey() to get the actual crypto.PublicKey
	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	// Finally, we can convert back to an *rsa.PublicKey
	pub := pubCrypto.(*rsa.PublicKey)

	// After this, it's encoding to PEM - same as always
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	})

	return encoded, nil
}
