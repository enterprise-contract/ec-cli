package pipeline

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

//CheckoutRepo is used as an alias for git.PlainClone in order to facilitate testing
var CheckoutRepo = git.PlainClone

//PolicySource in an interface representing the location of policies.
//Must implement the getPolicies() and getPolicyDir() methods.
type PolicySource interface {
	getPolicies(dest string) error
	getPolicyDir() string
}

//PolicyRepo is a struct representing a repository storing policy data.
type PolicyRepo struct {
	PolicyDir string
	RepoURL   string
	RepoRef   string
}

func (p *PolicyRepo) getPolicyDir() string {
	return p.PolicyDir
}
func (p *PolicyRepo) getPolicies(dest string) error {
	// Checkout policy repo into work directory.
	_, err := CheckoutRepo(dest, false, &git.CloneOptions{
		URL:           p.RepoURL,
		Progress:      nil,
		ReferenceName: plumbing.NewBranchReferenceName(p.RepoRef),
		SingleBranch:  true,
	})
	return err
}
