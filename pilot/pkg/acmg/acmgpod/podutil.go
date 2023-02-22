// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acmgpod

import (
	"istio.io/istio/pilot/pkg/acmg"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/api/label"
	"istio.io/api/mesh/v1alpha1"
	"istio.io/pkg/log"
)

func WorkloadFromPod(pod *corev1.Pod) acmg.Workload {
	var containers, ips []string
	for _, container := range pod.Spec.Containers {
		containers = append(containers, container.Name)
	}
	for _, ip := range pod.Status.PodIPs {
		ips = append(ips, ip.IP)
	}

	var controllerName, controllerKind string
	for _, ref := range pod.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			controllerName, controllerKind = ref.Name, ref.Kind
			break
		}
	}

	return acmg.Workload{
		UID:               string(pod.UID),
		Name:              pod.Name,
		Namespace:         pod.Namespace,
		Labels:            pod.Labels, // TODO copy?
		ServiceAccount:    pod.Spec.ServiceAccountName,
		NodeName:          pod.Spec.NodeName,
		HostNetwork:       pod.Spec.HostNetwork,
		PodIP:             pod.Status.PodIP,
		PodIPs:            ips,
		CreationTimestamp: pod.CreationTimestamp.Time,
		WorkloadMetadata: acmg.WorkloadMetadata{
			GenerateName:   pod.GenerateName,
			Containers:     containers,
			ControllerName: controllerName,
			ControllerKind: controllerKind,
		},
	}
}

func hasPodIP(pod *corev1.Pod) bool {
	return pod.Status.PodIP != ""
}

func isRunning(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodRunning
}

func ShouldPodBeInIpset(namespace *corev1.Namespace, pod *corev1.Pod, meshMode string, ignoreNotRunning bool) bool {
	// Pod must:
	// - Be running
	// - Have an IP address
	// - Ambient mesh not be off
	// - Cannot have a legacy label (istio.io/rev or istio-injection=enabled)
	// - If mesh is in namespace mode, must be in active namespace
	if (ignoreNotRunning || (isRunning(pod) && hasPodIP(pod))) &&
		meshMode != AcmgMeshOff.String() &&
		!HasLegacyLabel(pod.GetLabels()) &&
		!PodHasOptOut(pod) &&
		IsNamespaceActive(namespace, meshMode) {
		return true
	}

	return false
}

// @TODO Interim function for waypoint proxy, to be replaced after design meeting
func PodHasOptOut(pod *corev1.Pod) bool {
	if val, ok := pod.Labels["acmg-type"]; ok {
		return val == "waypoint" || val == "none"
	}
	return false
}

func IsNamespaceActive(namespace *corev1.Namespace, meshMode string) bool {
	// Must:
	// - MeshConfig be in an "ON" mode
	// - MeshConfig must be in a "DEFAULT" mode, plus:
	//   - Namespace cannot have "legacy" labels (ie. istio.io/rev or istio-injection=enabled)
	//   - Namespace must have label istio.io/dataplane-mode=ambient
	if meshMode == AcmgMeshOn.String() ||
		(meshMode == AcmgMeshNamespace.String() &&
			namespace != nil &&
			!HasLegacyLabel(namespace.GetLabels()) &&
			namespace.GetLabels()["istio.io/dataplane-mode"] == "acmg") {
		return true
	}

	return false
}

func HasSelectors(lbls map[string]string, selectors []labels.Selector) bool {
	for _, sel := range selectors {
		if sel.Matches(labels.Set(lbls)) {
			return true
		}
	}
	return false
}

var LegacyLabelSelector = []*metav1.LabelSelector{
	{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "istio-injection",
				Operator: metav1.LabelSelectorOpIn,
				Values: []string{
					"enabled",
				},
			},
		},
	},
	{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      label.IoIstioRev.Name,
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	},
}

var LegacySelectors = ConvertDisabledSelectors(LegacyLabelSelector)

func ConvertDisabledSelectors(selectors []*metav1.LabelSelector) []labels.Selector {
	res := make([]labels.Selector, 0, len(selectors))
	for _, k := range selectors {
		s, err := metav1.LabelSelectorAsSelector(k)
		if err != nil {
			log.Errorf("failed to convert label selector: %v", err)
			continue
		}
		res = append(res, s)
	}
	return res
}

// We do not support the istio.io/rev or istio-injection sidecar labels
// If a pod or namespace has these labels, ambient mesh will not be applied
// to that namespace
func HasLegacyLabel(lbl map[string]string) bool {
	for _, sel := range LegacySelectors {
		if sel.Matches(labels.Set(lbl)) {
			return true
		}
	}

	return false
}

const (
	//AcmgMeshNamespace = v1alpha1.MeshConfig_AcmgMeshConfig_DEFAULT
	//AcmgMeshOff       = v1alpha1.MeshConfig_AcmgMeshConfig_OFF
	//AcmgMeshOn        = v1alpha1.MeshConfig_AcmgMeshConfig_ON
	AcmgMeshNamespace = v1alpha1.MeshConfig_AmbientMeshConfig_DEFAULT
	AcmgMeshOff       = v1alpha1.MeshConfig_AmbientMeshConfig_OFF
	AcmgMeshOn        = v1alpha1.MeshConfig_AmbientMeshConfig_ON
)
