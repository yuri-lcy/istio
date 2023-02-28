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

package ambient

import (
	klabels "k8s.io/apimachinery/pkg/labels"

	ipsetlib "istio.io/istio/cni/pkg/ipset"
	"istio.io/istio/pkg/config/constants"
	"istio.io/pkg/env"
)

var (
	PodNamespace = env.RegisterStringVar("SYSTEM_NAMESPACE", constants.IstioSystemNamespace, "pod's namespace").Get()
	PodName      = env.RegisterStringVar("POD_NAME", "", "").Get()
	NodeName     = env.RegisterStringVar("NODE_NAME", "", "").Get()
	Revision     = env.RegisterStringVar("REVISION", "", "").Get()
	HostIP       = env.RegisterStringVar("HOST_IP", "", "").Get()
)

var Ipset = &ipsetlib.IPSet{
	Name: "ztunnel-pods-ips",
}

var ambientSelectors = klabels.SelectorFromValidatedSet(map[string]string{
	constants.DataplaneMode: constants.DataplaneModeAmbient,
})

type AmbientArgs struct {
	SystemNamespace string
	Revision        string
	KubeConfig      string
}
