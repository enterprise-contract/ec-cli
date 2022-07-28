package image

import (
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

type invocation struct {
	ConfigSource map[string]interface{} `json:"configSource"`
	Parameters   map[string]string      `json:"parameters"`
	Environment  map[string]interface{} `json:"environment"`
}

type materials struct {
	Uri    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type predicate struct {
	Invocation  invocation             `json:"invocation"`
	BuildType   string                 `json:"buildType"`
	Metadata    map[string]interface{} `json:"metadata"`
	Builder     map[string]interface{} `json:"builder"`
	BuildConfig map[string]interface{} `json:"buildConfig"`
	Materials   []materials            `json:"materials"`
}

type attestation struct {
	Predicate     predicate                `json:"predicate"`
	PredicateType string                   `json:"predicateType"`
	Subject       []map[string]interface{} `json:"subject"`
	Type          string                   `json:"_type"`
}

func (a *attestation) NewGitSource() (*GitSource, error) {
	repoUrl := a.getBuildSCM()
	sha := a.getBuildCommitSha()

	if repoUrl != "" && sha != "" {
		return &GitSource{
			repoUrl:   a.getBuildSCM(),
			commitSha: a.getBuildCommitSha(),
		}, nil
	}
	return nil, errors.New(
		fmt.Sprintf("there is no authorization source in attestation. sha: %v, url: %v", repoUrl, sha),
	)
}

func NewK8sSource(server, namespace, resource string) (*K8sSource, error) {
	return &K8sSource{
		namespace: namespace,
		server:    server,
		resource:  resource,
	}, nil
}

// get the last commit used for the component build
func (a *attestation) getBuildCommitSha() string {
	sha := "6c1f093c0c197add71579d392da8a79a984fcd62"
	if len(a.Predicate.Materials) == 1 {
		sha = a.Predicate.Materials[0].Digest["sha1"]
	}
	log.Debugf("using commit with sha: '%v'", sha)
	return sha
}

// the git url used for the component build
func (a *attestation) getBuildSCM() string {
	uri := "https://github.com/joejstuart/ec-cli.git"
	if len(a.Predicate.Materials) == 1 {
		uri = a.Predicate.Materials[0].Uri
	}
	log.Debugf("using repo '%v'", uri)
	return uri
}
