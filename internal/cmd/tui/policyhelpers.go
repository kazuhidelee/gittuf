// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"strings"

	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/gittuf/gittuf/internal/tuf"
)

type rule struct {
<<<<<<< HEAD
	name      string
	pattern   string
	key       string
	threshold int
}

// getCurrRules returns the current rules from the policy file.
func getCurrRules(ctx context.Context, o *options) []rule {
=======
	name    string
	pattern string
	key     string
}

// getCurrRules returns the current rules from the policy file
func getCurrRules(o *options) []rule {
>>>>>>> 987b1215 (*: Read access prototype)
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return nil
	}

<<<<<<< HEAD
	rules, err := repo.ListRules(ctx, o.targetRef)
=======
	rules, err := repo.ListRules(context.Background(), o.targetRef)
>>>>>>> 987b1215 (*: Read access prototype)
	if err != nil {
		return nil
	}

	var currRules = make([]rule, len(rules))
	for i, r := range rules {
		currRules[i] = rule{
<<<<<<< HEAD
			name:      r.Delegation.ID(),
			pattern:   strings.Join(r.Delegation.GetProtectedNamespaces(), ", "),
			key:       strings.Join(r.Delegation.GetPrincipalIDs().Contents(), ", "),
			threshold: r.Delegation.GetThreshold(),
=======
			name:    r.Delegation.ID(),
			pattern: strings.Join(r.Delegation.GetProtectedNamespaces(), ", "),
			key:     strings.Join(r.Delegation.GetPrincipalIDs().Contents(), ", "),
>>>>>>> 987b1215 (*: Read access prototype)
		}
	}
	return currRules
}

<<<<<<< HEAD
// repoAddRule adds a rule to the policy file.
func repoAddRule(ctx context.Context, o *options, rule rule, authorizedPrincipalIDs []string) error {
=======
// repoAddRule adds a rule to the policy file
func repoAddRule(o *options, rule rule, keyPath []string) error {
>>>>>>> 987b1215 (*: Read access prototype)
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}

<<<<<<< HEAD
	return repo.AddDelegation(ctx, signer, o.policyName, rule.name, authorizedPrincipalIDs, []string{rule.pattern}, rule.threshold, true)
}

// repoUpdateRule updates an existing rule in the policy file.
func repoUpdateRule(ctx context.Context, o *options, r rule, authorizedPrincipalIDs []string) error {
=======
	authorizedPrincipalIDs := []string{}
	for _, key := range keyPath {
		key, err := gittuf.LoadPublicKey(key)
		if err != nil {
			return err
		}

		authorizedPrincipalIDs = append(authorizedPrincipalIDs, key.ID())
	}
	res := repo.AddDelegation(context.Background(), signer, o.policyName, rule.name, authorizedPrincipalIDs, []string{rule.pattern}, 1, tuf.ScopeAll, "", tuf.AccessReadWrite, true)

	return res
}

// repoRemoveRule removes a rule from the policy file
func repoRemoveRule(o *options, rule rule) error {
>>>>>>> 987b1215 (*: Read access prototype)
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}
<<<<<<< HEAD

	return repo.UpdateDelegation(ctx, signer, o.policyName, r.name, authorizedPrincipalIDs, []string{r.pattern}, r.threshold, true)
}

// repoRemoveRule removes a rule from the policy file.
func repoRemoveRule(ctx context.Context, o *options, rule rule) error {
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}
	return repo.RemoveDelegation(ctx, signer, o.policyName, rule.name, true)
}

// repoReorderRules reorders the rules in the policy file.
func repoReorderRules(ctx context.Context, o *options, rules []rule) error {
=======
	return repo.RemoveDelegation(context.Background(), signer, o.policyName, rule.name, true)
}

// repoReorderRules reorders the rules in the policy file
func repoReorderRules(o *options, rules []rule) error {
>>>>>>> 987b1215 (*: Read access prototype)
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}

	ruleNames := make([]string, len(rules))
	for i, r := range rules {
		ruleNames[i] = r.name
	}

<<<<<<< HEAD
	return repo.ReorderDelegations(ctx, signer, o.policyName, ruleNames, true)
=======
	return repo.ReorderDelegations(context.Background(), signer, o.policyName, ruleNames, true)
>>>>>>> 987b1215 (*: Read access prototype)
}
