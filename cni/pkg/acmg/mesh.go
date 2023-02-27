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
	"encoding/json"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/mesh/kubemesh"
	"istio.io/pkg/version"
)

const (
	defaultMeshConfigMapName = "istio"
	configMapKey             = "mesh"
)

func (s *Server) initMeshConfiguration(args AcmgArgs) {
	log.Infof("Initializing mesh configuration")

	defer func() {
		if s.environment.Watcher != nil {
			log.Infof("mesh configuration: %s", mesh.PrettyFormatOfMeshConfig(s.environment.Mesh()))
			log.Infof("version: %s", version.Info.String())
			argsdump, _ := json.MarshalIndent(args, "", "    ")
			log.Infof("flags: %s", argsdump)
		}
	}()

	multiWatch := features.SharedMeshConfig != ""

	configMapName := getMeshConfigMapName(args.Revision)
	multiWatcher := kubemesh.NewConfigMapWatcher(
		s.kubeClient, args.SystemNamespace, configMapName, configMapKey, multiWatch, s.ctx.Done())
	s.environment.Watcher = multiWatcher

	if multiWatch {
		kubemesh.AddUserMeshConfig(s.kubeClient, multiWatcher, args.SystemNamespace, configMapKey, features.SharedMeshConfig, s.ctx.Done())
	}
}

func getMeshConfigMapName(revision string) string {
	name := defaultMeshConfigMapName
	if revision == "" || revision == "default" {
		return name
	}
	return name + "-" + revision
}
