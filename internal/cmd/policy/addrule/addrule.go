// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package addrule

import (
	"github.com/gittuf/gittuf/experimental/gittuf"
	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/cmd/policy/persistent"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/spf13/cobra"
)

type options struct {
	p                      *persistent.Options
	policyName             string
	ruleName               string
	authorizedKeys         []string
	authorizedPrincipalIDs []string
	rulePatterns           []string
	threshold              int

	isScopeTypeAll     bool
	isScopeTypeLatestN bool
	isScopeTypeRange   bool
	scope              string

	isReadWrite bool
	isReadOnly  bool
	isWriteOnly bool
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.policyName,
		"policy-name",
		policy.TargetsRoleName,
		"name of policy file to add rule to",
	)

	cmd.Flags().StringVar(
		&o.ruleName,
		"rule-name",
		"",
		"name of rule",
	)
	cmd.MarkFlagRequired("rule-name") //nolint:errcheck

	cmd.Flags().StringArrayVar(
		&o.authorizedKeys,
		"authorize-key",
		[]string{},
		"authorized public key for rule",
	)
	cmd.Flags().MarkDeprecated("authorize-key", "use --authorize instead") //nolint:errcheck

	cmd.Flags().StringArrayVar(
		&o.authorizedPrincipalIDs,
		"authorize",
		[]string{},
		"authorize the principal IDs for the rule",
	)
	cmd.MarkFlagsOneRequired("authorize", "authorize-key")

	cmd.Flags().StringArrayVar(
		&o.rulePatterns,
		"rule-pattern",
		[]string{},
		"patterns used to identify namespaces rule applies to",
	)
	cmd.MarkFlagRequired("rule-pattern") //nolint:errcheck

	cmd.Flags().IntVar(
		&o.threshold,
		"threshold",
		1,
		"threshold of required valid signatures",
	)

	cmd.Flags().BoolVarP(
		&o.isScopeTypeAll,
		"scope-all",
		"",
		true,
		"rule applies to all states",
	)
	cmd.Flags().BoolVarP(
		&o.isScopeTypeLatestN,
		"scope-latest-n",
		"",
		false,
		"rule applies to the latest N states",
	)
	cmd.Flags().BoolVarP(
		&o.isScopeTypeRange,
		"scope-range",
		"",
		false,
		"rule applies to the states in the specified range",
	)
	cmd.MarkFlagsMutuallyExclusive("scope-all", "scope-latest-n", "scope-range")

	cmd.Flags().StringVarP(
		&o.scope,
		"scope",
		"",
		"",
		"scope of the rule (only applicable if scope type is latest-n or range",
	)
	cmd.MarkFlagsRequiredTogether("scope-latest-n", "scope")
	cmd.MarkFlagsRequiredTogether("scope-range", "scope")

	cmd.Flags().BoolVarP(
		&o.isReadWrite,
		"read-write",
		"",
		true,
		"authorize both read and write access",
	)
	cmd.Flags().BoolVarP(
		&o.isReadOnly,
		"read",
		"",
		false,
		"authorize only read access",
	)
	cmd.Flags().BoolVarP(
		&o.isWriteOnly,
		"write",
		"",
		false,
		"authorize only write access",
	)
	cmd.MarkFlagsMutuallyExclusive("read-write", "read", "write")
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	var scopeType tuf.ScopeType
	switch {
	case o.isScopeTypeAll:
		scopeType = tuf.ScopeAll
	case o.isScopeTypeLatestN:
		scopeType = tuf.ScopeLatestN
	case o.isScopeTypeRange:
		scopeType = tuf.ScopeRange
	}

	var access tuf.AccessType
	switch {
	case o.isReadWrite:
		access = tuf.AccessReadWrite
	case o.isReadOnly:
		access = tuf.AccessReadOnly
	case o.isWriteOnly:
		access = tuf.AccessWriteOnly
	}

	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}

	authorizedPrincipalIDs := []string{}
	for _, key := range o.authorizedKeys {
		key, err := gittuf.LoadPublicKey(key)
		if err != nil {
			return err
		}

		authorizedPrincipalIDs = append(authorizedPrincipalIDs, key.ID())
	}
	authorizedPrincipalIDs = append(authorizedPrincipalIDs, o.authorizedPrincipalIDs...)

	opts := []trustpolicyopts.Option{}
	if o.p.WithRSLEntry {
		opts = append(opts, trustpolicyopts.WithRSLEntry())
	}
	return repo.AddDelegation(cmd.Context(), signer, o.policyName, o.ruleName, authorizedPrincipalIDs, o.rulePatterns, o.threshold, scopeType, o.scope, access, true, opts...)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "add-rule",
		Short:             "Add a new rule to a policy file",
		Long:              `The 'add-rule' command adds a new rule to a gittuf policy file. Each rule contains a name ('--rule-name') for the rule, one or more principals ('--authorize') who are allowed to sign within the scope of the rule, a set of rule patterns ('--rule-pattern') defining the namespaces or paths the rule governs, and a signature threshold ('--threshold'), which is the minimum number of valid signatures required to satisfy the rule. Principals can be specified by their principal IDs. By default, the main policy file (targets) is used, which can be overridden with the '--policy-name' flag.`,
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
