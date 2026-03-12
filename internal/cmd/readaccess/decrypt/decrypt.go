// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package decrypt

import (
	"github.com/gittuf/gittuf/experimental/gittuf"
	sslibed "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/encrypterdecrypter"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/spf13/cobra"
)

type options struct {
	commitHash string
	keyPath    string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.commitHash,
		"commit-hash",
		"",
		"The hash of the commit to decrypt",
	)

	cmd.Flags().StringVar(
		&o.keyPath,
		"key-path",
		"",
		"The path to the private key for the principal, used for decrypting the appropriate metadata",
	)
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	var decrypter sslibed.Decrypter

	if o.keyPath == "" {
		decrypter, err = gittuf.LoadEncrypterDecrypterFromGitConfig(repo)
		if err != nil {
			return err
		}
	} else {
		decrypter, err = gittuf.LoadEncrypterDecrypter(repo, o.keyPath)
		if err != nil {
			return err
		}
	}

	var commitHash gitinterface.Hash

	if o.commitHash == "" {
		gitinterfaceRepo, err := gitinterface.LoadRepository(".")
		if err != nil {
			return err
		}

		currentRef, err := gitinterfaceRepo.GetSymbolicReferenceTarget("HEAD")
		if err != nil {
			return err
		}

		commitHash, err = gitinterfaceRepo.GetReference(currentRef)
		if err != nil {
			return err
		}
	} else {
		commitHash, err = gitinterface.NewHash(o.commitHash)
		if err != nil {
			return err
		}
	}

	return repo.DecryptState(cmd.Context(), commitHash, decrypter)
}

func New() *cobra.Command {
	o := options{}
	cmd := &cobra.Command{
		Use:               "decrypt",
		Short:             "Decrypt a commit",
		Long:              "Decrypt a commit. If no commit hash is specified, the commit on the tip of the current branch is assumed",
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
