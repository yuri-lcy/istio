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

package acmg

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/api/mesh/v1alpha1"
)

type ExecList struct {
	Cmd  string
	Args []string
}

func newExec(cmd string, args []string) *ExecList {
	return &ExecList{
		Cmd:  cmd,
		Args: args,
	}
}

func executeOutput(cmd string, args ...string) (string, error) {
	externalCommand := exec.Command(cmd, args...)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	externalCommand.Stdout = stdout
	externalCommand.Stderr = stderr

	err := externalCommand.Run()

	if err != nil || len(stderr.Bytes()) != 0 {
		return stderr.String(), err
	}

	return strings.TrimSuffix(stdout.String(), "\n"), err
}

func execute(cmd string, args ...string) error {
	log.Debugf("Running command: %s %s", cmd, strings.Join(args, " "))
	externalCommand := exec.Command(cmd, args...)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	externalCommand.Stdout = stdout
	externalCommand.Stderr = stderr

	err := externalCommand.Run()

	if len(stdout.String()) != 0 {
		log.Debugf("Command output: \n%v", stdout.String())
	}

	if err != nil || len(stderr.Bytes()) != 0 {
		log.Debugf("Command error output: \n%v", stderr.String())
		return errors.New(stderr.String())
	}

	return nil
}

func (s *Server) matchesAmbientSelectors(lbl map[string]string) (bool, error) {
	sel, err := metav1.LabelSelectorAsSelector(&ambientSelectors)
	if err != nil {
		return false, fmt.Errorf("failed to parse ambient selectors: %v", err)
	}

	return sel.Matches(labels.Set(lbl)), nil
}

func (s *Server) matchesDisabledSelectors(lbl map[string]string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, selector := range s.disabledSelectors {
		sel, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return false, fmt.Errorf("failed to parse disabled selectors: %v", err)
		}
		if sel.Matches(labels.Set(lbl)) {
			return true, nil
		}
	}

	return false, nil
}

func podOnMyNode(pod *corev1.Pod) bool {
	return pod.Spec.NodeName == NodeName
}

func (s *Server) isAmbientGlobal() bool {
	return s.meshMode == v1alpha1.MeshConfig_AmbientMeshConfig_ON
}

func (s *Server) isAmbientNamespaced() bool {
	return s.meshMode == v1alpha1.MeshConfig_AmbientMeshConfig_DEFAULT
}

func (s *Server) isAmbientOff() bool {
	return s.meshMode == v1alpha1.MeshConfig_AmbientMeshConfig_OFF
}

func getEnvFromPod(pod *corev1.Pod, envName string) string {
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == envName {
				return env.Value
			}
		}
	}
	return ""
}
