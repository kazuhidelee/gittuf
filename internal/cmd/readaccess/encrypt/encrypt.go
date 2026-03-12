// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package encrypt

import (
	"github.com/gittuf/gittuf/experimental/gittuf"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

type options struct {
	refName       string
	commitMessage string
	keyPath       string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.refName,
		"ref-name",
		"arcanum-evaluation",
		"The reference to write the new encrypted commit to",
	)

	cmd.Flags().StringVar(
		&o.keyPath,
		"key-path",
		"",
		"The path to the private key for the principal, used for signing new metadata",
	)

	cmd.Flags().StringVar(
		&o.commitMessage,
		"commit-message",
		"",
		"The commit message",
	)
	cmd.MarkFlagRequired("commit-message") //nolint:errcheck
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	var signer sslibdsse.SignerVerifier

	if o.keyPath != "" {
		signer, err = gittuf.LoadSigner(repo, o.keyPath)
		if err != nil {
			return err
		}
	} else {
		signer, err = gittuf.LoadSignerFromGitConfig(repo)
		if err != nil {
			return err
		}
	}

	return repo.EncryptState(cmd.Context(), o.refName, o.commitMessage, signer)
}

func New() *cobra.Command {
	o := options{}
	cmd := &cobra.Command{
		Use:               "encrypt",
		Short:             "Encrypt a commit",
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
