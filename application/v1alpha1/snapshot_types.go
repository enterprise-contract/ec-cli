/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SnapshotSpec defines the desired state of Snapshot
type SnapshotSpec struct {

	// Application is a reference to the name of an Application resource within the same namespace, which defines the target application for the Snapshot (when used with a Binding).
	Application string `json:"application"`

	// DisplayName is a user-visible, user-definable name for the resource (and is not used for any functional behaviour)
	DisplayName string `json:"displayName,omitempty"`

	// DisplayDescription is a user-visible, user definable description for the resource (and is not used for any functional behaviour)
	DisplayDescription string `json:"displayDescription,omitempty"`

	// Components field contains the sets of components to deploy as part of this snapshot.
	Components []SnapshotComponent `json:"components,omitempty"`

	// Artifacts is a placeholder section for 'artifact links' we want to maintain to other AppStudio resources.
	// See Environment API doc for details.
	Artifacts SnapshotArtifacts `json:"artifacts,omitempty"`
}

// SnapshotComponent
type SnapshotComponent struct {

	// Name is the name of the component
	Name string `json:"name"`

	// ContainerImage is the container image to use when deploying the component, as part of a Snapshot
	ContainerImage string `json:"containerImage"`

	// Source describes the Component source.
	// Optional.
	// +optional
	Source ComponentSource `json:"source,omitempty"`
}

// SnapshotArtifacts is a placeholder section for 'artifact links' we want to maintain to other AppStudio resources.
//
// For example: here I'm imagining we might want to keep track of container image <=> (source code repo, commit sha) links,
// Which might be useful to present to the user within the UI.
type SnapshotArtifacts struct {

	// NOTE: This field (and struct) are placeholders.
	// - Until this API is stabilized, consumers of the API may store any unstructured JSON/YAML data here,
	//   but no backwards compatibility will be preserved.
	UnstableFields *apiextensionsv1.JSON `json:"unstableFields,omitempty"`
}

// SnapshotStatus defines the observed state of Snapshot
type SnapshotStatus struct {
	// Conditions represent the latest available observations for the Snapshot
	// +optional
	Conditions []metav1.Condition `json:"conditions"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Snapshot is the Schema for the snapshots API
// +kubebuilder:resource:path=snapshots,shortName=as;snapshot
type Snapshot struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SnapshotSpec   `json:"spec,omitempty"`
	Status SnapshotStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SnapshotList contains a list of Snapshot
type SnapshotList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Snapshot `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Snapshot{}, &SnapshotList{})
}
