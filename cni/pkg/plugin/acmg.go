package plugin

import (
	"context"
	"fmt"
	"istio.io/istio/cni/pkg/acmg"
	"istio.io/istio/pilot/pkg/acmg/acmgpod"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
)

func checkAcmg(conf Config, acmgConfig acmg.AcmgConfigFile, podName, podNamespace, podIfname string, podIPs []net.IPNet) (bool, error) {
	if acmgConfig.Mode == acmg.AcmgMeshOff.String() {
		return false, nil
	}

	if !acmgConfig.NodeProxyReady {
		return false, fmt.Errorf("nodeproxy not ready")
	}

	client, err := newKubeClient(conf)
	if err != nil {
		return false, err
	}

	if client == nil {
		return false, nil
	}

	pod, err := client.CoreV1().Pods(podNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	ns, err := client.CoreV1().Namespaces().Get(context.Background(), podNamespace, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if acmgpod.HasLegacyLabel(pod.Labels) || acmgpod.HasLegacyLabel(ns.Labels) {
		return false, fmt.Errorf("ambient: pod %s/%s or namespace has legacy labels", podNamespace, podName)
	}

	if acmgpod.HasSelectors(ns.Labels, acmgpod.ConvertDisabledSelectors(acmgConfig.DisabledSelectors)) {
		return false, fmt.Errorf("acmg: namespace %s/%s has disabled selectors", podNamespace, podName)
	}

	if acmgpod.ShouldPodBeInIpset(ns, pod, acmgConfig.Mode, true) {
		acmg.NodeName = pod.Spec.NodeName

		acmg.HostIP, err = acmg.GetHostIP(client)
		if err != nil || acmg.HostIP == "" {
			return false, fmt.Errorf("error getting host IP: %v", err)
		}

		// Can't set this on GKE, but needed in AWS.. so silently ignore failures
		_ = acmg.SetProc("/proc/sys/net/ipv4/conf/"+podIfname+"/rp_filter", "0")

		for _, ip := range podIPs {
			acmg.AddPodToMesh(pod, ip.IP.String())
		}
		return true, nil
	}

	return false, nil
}
