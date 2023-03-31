// Copyright 2022 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package kind

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path"
	"sync"
	"time"

	"github.com/phayes/freeport"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	util "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	w "k8s.io/client-go/tools/watch"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	k "sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/acceptance/kubernetes/types"
	"github.com/enterprise-contract/ec-cli/acceptance/kustomize"
	"github.com/enterprise-contract/ec-cli/acceptance/log"
)

type key int

const testStateKey = key(0)

// we don't want to bootstrap two clusters simultaniously
var clusterMutex = sync.Mutex{}

// cluster consumers, we wait for every consumer to stop using the cluster
// before we shutdown the cluster
var clusterGroup = sync.WaitGroup{}

// make sure we try to destroy the cluster only once
var destroy = sync.Once{}

// single instance of Kind cluster
var globalCluster *kindCluster

type testState struct {
	namespace string
	policy    string
	taskRun   string
	snapshot  string
}

func (n testState) Key() any {
	return testStateKey
}

const clusterConfiguration = `kind: ClusterConfiguration
apiServer:
  extraArgs:
    "service-node-port-range": "1-65535"` // the extra port range for accessing the image registry at the random port

// We pass the registry port to Kustomize via an environment variable, we spawn
// Kustomize from the process runnning the test, to prevent concurrency issues
// with many tests running more than one kustomization when we modify the
// environment we use this mutex
var envMutex = sync.Mutex{}

type kindCluster struct {
	name           string
	kubeconfigPath string
	registryPort   int32
	provider       *k.Provider
	config         *rest.Config
	client         *kubernetes.Clientset
	dynamic        dynamic.Interface
	mapper         meta.RESTMapper
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (k *kindCluster) Up(_ context.Context) bool {
	if k.provider == nil || k.name == "" {
		return false
	}

	nodes, err := k.provider.ListNodes(k.name)

	return len(nodes) > 0 && err == nil
}

// Start creates a new randomly named Kind cluster and provisions it for use;
// meaning: the hack/test kustomization will applied to the cluster, the ec-cli
// and the Tekton Task bundle images will be pushed to the registry running in
// the cluster.
func Start(ctx context.Context) (context.Context, types.Cluster, error) {
	clusterMutex.Lock()
	defer clusterMutex.Unlock()

	defer func() {
		if globalCluster != nil {
			// we were given or we started the cluster, so count us as a
			// consumer of the cluster
			clusterGroup.Add(1)
		}
	}()

	if globalCluster != nil {
		return ctx, globalCluster, nil
	}

	configDir, err := os.MkdirTemp("", "ec-acceptance.*")
	if err != nil {
		return ctx, nil, err
	}

	kCluster := kindCluster{
		name:     fmt.Sprintf("acceptance-%d", rand.Uint64()),
		provider: k.NewProvider(k.ProviderWithLogger(log.LoggerFor(ctx))),
	}

	if port, err := freeport.GetFreePort(); err != nil {
		return ctx, nil, err
	} else {
		kCluster.registryPort = int32(port)
	}

	kCluster.kubeconfigPath = path.Join(configDir, "kubeconfig")

	if err := kCluster.provider.Create(kCluster.name,
		k.CreateWithV1Alpha4Config(&v1alpha4.Cluster{
			TypeMeta: v1alpha4.TypeMeta{
				Kind:       "Cluster",
				APIVersion: "kind.x-k8s.io/v1alpha4",
			},
			Nodes: []v1alpha4.Node{
				{
					Role: v1alpha4.ControlPlaneRole,
					KubeadmConfigPatches: []string{
						clusterConfiguration,
					},
					// exposes the registry port to the host OS
					ExtraPortMappings: []v1alpha4.PortMapping{
						{
							ContainerPort: kCluster.registryPort,
							HostPort:      kCluster.registryPort,
							Protocol:      v1alpha4.PortMappingProtocolTCP,
							ListenAddress: "127.0.0.1",
						},
					},
				},
			},
		}),
		k.CreateWithKubeconfigPath(kCluster.kubeconfigPath)); err != nil {
		return ctx, &kCluster, err
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kCluster.kubeconfigPath

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil)

	if kCluster.config, err = clientConfig.ClientConfig(); err != nil {
		return ctx, &kCluster, err
	}

	if kCluster.dynamic, err = dynamic.NewForConfig(kCluster.config); err != nil {
		return ctx, &kCluster, err
	}

	if kCluster.client, err = kubernetes.NewForConfig(kCluster.config); err != nil {
		return ctx, &kCluster, err
	}

	discovery := discovery.NewDiscoveryClientForConfigOrDie(kCluster.config)

	if resources, err := restmapper.GetAPIGroupResources(discovery); err != nil {
		return ctx, &kCluster, err
	} else {
		kCluster.mapper = restmapper.NewDiscoveryRESTMapper(resources)
	}

	yaml, err := renderTestConfiguration(&kCluster)
	if err != nil {
		return ctx, &kCluster, err
	}

	err = applyConfiguration(ctx, &kCluster, yaml)
	if err != nil {
		return ctx, &kCluster, err
	}

	err = kCluster.buildCliImage(ctx)
	if err != nil {
		return ctx, &kCluster, err
	}

	err = kCluster.buildTaskBundleImage(ctx)
	if err != nil {
		return ctx, &kCluster, err
	}

	globalCluster = &kCluster

	return ctx, &kCluster, nil
}

// renderTestConfiguration renders the hack/test Kustomize directory into a
// multi-document YAML. The port for the cluster registry, needed to configure
// the k8s Service for it is passed via REGISTRY_PORT environment variable
func renderTestConfiguration(k *kindCluster) (yaml []byte, err error) {
	envMutex.Lock()
	if err := os.Setenv("REGISTRY_PORT", fmt.Sprint(k.registryPort)); err != nil {
		return nil, err
	}

	defer func() {
		_ = os.Unsetenv("REGISTRY_PORT") // ignore errors
		envMutex.Unlock()
	}()

	return kustomize.Render(path.Join("test"))
}

// applyConfiguration runs equivalent of kubectl apply for each document in the
// definitions YAML
func applyConfiguration(ctx context.Context, k *kindCluster, definitions []byte) (err error) {
	reader := util.NewYAMLReader(bufio.NewReader(bytes.NewReader(definitions)))
	for {
		var definition []byte
		definition, err = reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return
		}

		var obj unstructured.Unstructured
		if err = yaml.Unmarshal(definition, &obj); err != nil {
			return
		}

		var mapping *meta.RESTMapping
		if mapping, err = k.mapper.RESTMapping(obj.GroupVersionKind().GroupKind()); err != nil {
			return
		}

		var c dynamic.ResourceInterface = k.dynamic.Resource(mapping.Resource)
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			c = c.(dynamic.NamespaceableResourceInterface).Namespace(obj.GetNamespace())
		}

		_, err = c.Apply(ctx, obj.GetName(), &obj, metav1.ApplyOptions{FieldManager: "application/apply-patch"})
		if err != nil {
			return
		}
	}

	err = waitForAvailableDeploymentsIn(ctx, k, "tekton-pipelines", "image-registry")

	return
}

// waitForAvailableDeploymentsIn makes sure that all deployments in the provided
// namespaces are available
func waitForAvailableDeploymentsIn(ctx context.Context, k *kindCluster, namespaces ...string) (err error) {
	for _, namespace := range namespaces {
		watcher := cache.NewListWatchFromClient(k.client.AppsV1().RESTClient(), "deployments", namespace, fields.Everything())

		a := newAvail()
		_, err = w.UntilWithSync(ctx, watcher, &appsv1.Deployment{}, nil, (&a).allAvailable)
	}

	return
}

// keeps track of what deployment is available, the available map is keyed by
// <namespace>/<name>, the value is either true - available, or false - not
// available
type avail struct {
	available map[string]bool
}

func newAvail() avail {
	return avail{
		available: map[string]bool{},
	}
}

// allAvailable is invoked by the watcher for each change to the object, the
// object's availablity is tracked and if all objects are available true is
// returned, stopping the watcher
func (a *avail) allAvailable(event watch.Event) (bool, error) {
	deployment := event.Object.(*appsv1.Deployment)

	for _, condition := range deployment.Status.Conditions {
		namespace := deployment.GetNamespace()
		name := deployment.GetName()

		if condition.Type == appsv1.DeploymentAvailable {
			a.available[namespace+"/"+name] = condition.Status == v1.ConditionTrue
			break
		}
	}

	for _, available := range a.available {
		if !available {
			return false, nil
		}
	}

	return true, nil
}

func (k *kindCluster) KubeConfig(ctx context.Context) (string, error) {
	if bytes, err := os.ReadFile(k.kubeconfigPath); err != nil {
		return "", err
	} else {
		return string(bytes), err
	}
}

func (k *kindCluster) Stop(ctx context.Context) error {
	if !k.Up(ctx) {
		return nil
	}

	// release cluster
	clusterGroup.Done()

	// wait for other cluster consumers to finish
	clusterGroup.Wait()

	destroy.Do(k.destroyCluster)

	return nil
}

func (k *kindCluster) destroyCluster() {
	defer func() {
		kindDir := path.Join(k.kubeconfigPath, "..")
		_ = os.RemoveAll(kindDir) // ignore errors
	}()

	// ignore error
	_ = k.provider.Delete(k.name, k.kubeconfigPath)
}
