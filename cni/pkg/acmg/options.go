package acmg

import (
	"istio.io/api/label"
	"istio.io/api/mesh/v1alpha1"
	ipsetlib "istio.io/istio/cni/pkg/ipset"
	"istio.io/istio/pkg/config/constants"
	"istio.io/pkg/env"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	PodNamespace = env.RegisterStringVar("SYSTEM_NAMESPACE", constants.IstioSystemNamespace, "pod's namespace").Get()
	PodName      = env.RegisterStringVar("POD_NAME", "", "").Get()
	NodeName     = env.RegisterStringVar("NODE_NAME", "", "").Get()
	Revision     = env.RegisterStringVar("REVISION", "", "").Get()
	HostIP       = env.RegisterStringVar("HOST_IP", "", "").Get()
)

type ConfigSourceAddressScheme string

const (
	Kubernetes ConfigSourceAddressScheme = "k8s"
)

const (
	dataplaneLabelAcmgValue = "acmg"

	AmbientMeshNamespace = v1alpha1.MeshConfig_AmbientMeshConfig_DEFAULT
	AmbientMeshOff       = v1alpha1.MeshConfig_AmbientMeshConfig_OFF
	AmbientMeshOn        = v1alpha1.MeshConfig_AmbientMeshConfig_ON
)

var Ipset = &ipsetlib.IPSet{
	Name: "nodeproxy-pods-ips",
}

var acmgSelectors metav1.LabelSelector = metav1.LabelSelector{
	MatchLabels: map[string]string{
		label.IoIstioDataplaneMode.Name: dataplaneLabelAcmgValue,
	},
}

type AcmgArgs struct {
	SystemNamespace string
	Revision        string
	KubeConfig      string
}
