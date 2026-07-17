// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package readaccess

import (
	"github.com/gittuf/gittuf/internal/cmd/readaccess/compression"
	"github.com/gittuf/gittuf/internal/cmd/readaccess/decrypt"
	"github.com/gittuf/gittuf/internal/cmd/readaccess/encrypt"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "read-access",
		Short:             "Operations related to read access control in gittuf",
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(compression.New())
	cmd.AddCommand(decrypt.New())
	cmd.AddCommand(encrypt.New())

	return cmd
}
