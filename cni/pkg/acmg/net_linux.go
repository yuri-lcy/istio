package acmg

import (
	"errors"
	"fmt"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"io/fs"
	ebpf "istio.io/istio/cni/pkg/ebpf/server"
	corev1 "k8s.io/api/core/v1"
	"net"
	"net/netip"
	"path"
	"path/filepath"
)

func buildEbpfArgsByIP(ip string, isNodeProxy, isRemove bool) (*ebpf.RedirectArgs, error) {
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip(%s): %v", ip, err)
	}
	veth, err := getVethWithDestinationOf(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}
	peerIndex, err := getPeerIndex(veth)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth peerIndex: %v", err)
	}

	peerNs, err := getNsNameFromNsID(veth.Attrs().NetNsID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ns name: %v", err)
	}

	mac, err := getMacFromNsIdx(peerNs, peerIndex)
	if err != nil {
		return nil, err
	}

	return &ebpf.RedirectArgs{
		IPAddrs:     []netip.Addr{ipAddr},
		MacAddr:     mac,
		Ifindex:     veth.Attrs().Index,
		PeerIndex:   peerIndex,
		PeerNs:      peerNs,
		IsNodeProxy: isNodeProxy,
		Remove:      isRemove,
	}, nil
}

func getMacFromNsIdx(ns string, ifIndex int) (net.HardwareAddr, error) {
	var hwAddr net.HardwareAddr
	err := netns.WithNetNSPath(fmt.Sprintf("/var/run/netns/%s", ns), func(netns.NetNS) error {
		link, err := netlink.LinkByIndex(ifIndex)
		if err != nil {
			return fmt.Errorf("failed to get link(%d) in ns(%s): %v", ifIndex, ns, err)
		}
		hwAddr = link.Attrs().HardwareAddr
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hwAddr, nil
}

func getPeerIndex(veth *netlink.Veth) (int, error) {
	return netlink.VethPeerIndex(veth)
}

func getNsNameFromNsID(nsid int) (string, error) {
	foundNs := errors.New("nsid found, stop iterating")
	nsName := ""
	err := filepath.WalkDir("/var/run/netns", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fd, err := unix.Open(p, unix.O_RDONLY, 0)
		if err != nil {
			log.Warnf("failed to open: %v", err)
			return nil
		}
		defer unix.Close(fd)

		id, err := netlink.GetNetNsIdByFd(fd)
		if err != nil {
			log.Warnf("failed to open: %v", err)
			return nil
		}
		if id == nsid {
			nsName = path.Base(p)
			return foundNs
		}
		return nil
	})
	if err == foundNs {
		return nsName, nil
	}
	return "", fmt.Errorf("failed to get namespace for %d", nsid)
}

func getVethWithDestinationOf(ip string) (*netlink.Veth, error) {
	link, err := getLinkWithDestinationOf(ip)
	if err != nil {
		return nil, err
	}
	veth, ok := link.(*netlink.Veth)
	if !ok {
		return nil, errors.New("not veth implemented CNI")
	}
	return veth, nil
}

func getLinkWithDestinationOf(ip string) (netlink.Link, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Dst: &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(32, 32)}},
		netlink.RT_FILTER_DST)
	if err != nil {
		return nil, err
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes found for %s", ip)
	}

	linkIndex := routes[0].LinkIndex
	return netlink.LinkByIndex(linkIndex)
}

func (s *Server) updateNodeProxyEBPF(pod *corev1.Pod, captureDNS bool) error {
	if s.ebpfServer == nil {
		return fmt.Errorf("uninitialized ebpf server")
	}

	ip := pod.Status.PodIP

	veth, err := getVethWithDestinationOf(ip)
	if err != nil {
		log.Warnf("failed to get device: %v", err)
	}
	peerIndex, err := getPeerIndex(veth)
	if err != nil {
		return fmt.Errorf("failed to get veth peerIndex: %v", err)
	}

	err = disableRPFiltersForLink(veth.Attrs().Name)
	if err != nil {
		log.Warnf("failed to disable procfs rp_filter for device %s: %v", veth.Attrs().Name, err)
	}

	args, err := buildEbpfArgsByIP(ip, true, false)
	if err != nil {
		return err
	}
	args.CaptureDNS = captureDNS
	log.Debugf("update nodeproxy ebpf args: %+v", args)

	// Now that we have the ip, the veth, and the ztunnel netns,
	// two things need to happen:
	// 1. We need to interact with the kernel to jump into the ztunnel net namespace
	// and create some local rules within that net namespace
	err = s.CreateEBPFRulesWithinNodeProxyNS(peerIndex, ip, args.PeerNs)
	if err != nil {
		return fmt.Errorf("failed to configure nodeproxy pod rules: %v", err)
	}

	// 2. We need to interact with the kernel to attach eBPF progs to ztunnel
	s.ebpfServer.AcceptRequest(args)

	return nil
}

func (s *Server) delNodeProxyEbpfOnNode() error {
	if s.ebpfServer == nil {
		return fmt.Errorf("uninitialized ebpf server")
	}

	args := &ebpf.RedirectArgs{
		Ifindex:     0,
		IsNodeProxy: true,
		Remove:      true,
	}
	log.Debugf("del nodeproxy ebpf args: %+v", args)
	s.ebpfServer.AcceptRequest(args)
	return nil
}
