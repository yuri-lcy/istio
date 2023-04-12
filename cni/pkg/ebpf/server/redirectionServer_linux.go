package server

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86"  ambient_redirect ../app/ambient_redirect.bpf.c
//go:generate sh -c "echo '// Copyright Istio Authors' > banner.tmp"
//go:generate sh -c "echo '//' >> banner.tmp"
//go:generate sh -c "echo '// Licensed under the Apache License, Version 2.0 (the \"License\");' >> banner.tmp"
//go:generate sh -c "echo '// you may not use this file except in compliance with the License.' >> banner.tmp"
//go:generate sh -c "echo '// You may obtain a copy of the License at' >> banner.tmp"
//go:generate sh -c "echo '//' >> banner.tmp"
//go:generate sh -c "echo '//     http://www.apache.org/licenses/LICENSE-2.0' >> banner.tmp"
//go:generate sh -c "echo '//' >> banner.tmp"
//go:generate sh -c "echo '// Unless required by applicable law or agreed to in writing, software' >> banner.tmp"
//go:generate sh -c "echo '// distributed under the License is distributed on an \"AS IS\" BASIS,' >> banner.tmp"
//go:generate sh -c "echo '// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.' >> banner.tmp"
//go:generate sh -c "echo '// See the License for the specific language governing permissions and' >> banner.tmp"
//go:generate sh -c "echo '// limitations under the License.\n' >> banner.tmp"
//go:generate sh -c "cat banner.tmp ambient_redirect_bpf.go > tmp.go && mv tmp.go ambient_redirect_bpf.go && rm banner.tmp"

import (
	"errors"
	"fmt"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/josharian/native"
	"golang.org/x/sys/unix"
	istiolog "istio.io/pkg/log"
	"os"
)

var log = istiolog.RegisterScope("ebpf", "acmg ebpf", 0)

const (
	FilesystemTypeBPFFS = unix.BPF_FS_MAGIC
	MapsRoot            = "/sys/fs/bpf"
	MapsPinpath         = "/sys/fs/bpf/ambient"
	CaptureDNSFlag      = uint8(1 << 0)

	QdiscKind            = "clsact"
	TcaBpfFlagActDiretct = 1 << 0 // refer to include/uapi/linux/pkt_cls.h TCA_BPF_FLAG_ACT_DIRECT
	TcPrioFilter         = 1      // refer to include/uapi/linux/pkt_sched.h TC_PRIO_FILLER
)

const (
	EBPFLogLevelNone uint32 = iota
	EBPFLogLevelInfo
	EBPFLogLevelDebug
)

var isBigEndian = native.IsBigEndian

type RedirectServer struct {
	redirectArgsChan             chan *RedirectArgs
	obj                          acmg_redirectObjects
	nodeProxyHostingressFd       uint32
	nodeProxyHostingressProgName string
	nodeProxyIngressFd           uint32
	nodeProxyIngressProgName     string
	inboundFd                    uint32
	inboundProgName              string
	outboundFd                   uint32
	outboundProgName             string
}

func (r *RedirectServer) attachTC(namespace string, ifindex uint32, direction string, fd uint32, name string) error {
	config := &tc.Config{}
	if namespace != "" {
		nsHdlr, err := ns.GetNS(fmt.Sprintf("/var/run/netns/%s", namespace))
		if err != nil {
			return err
		}
		defer nsHdlr.Close()
		config.NetNS = int(nsHdlr.Fd())
	}
	rtnl, err := tc.Open(config)
	if err != nil {
		return err
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Warnf("could not close rtnetlink socket: %v", err)
		}
	}()

	qdiscInfo := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: QdiscKind,
		},
	}
	// create qdisc on interface if not exists
	if err := rtnl.Qdisc().Add(&qdiscInfo); err != nil && !errors.Is(err, os.ErrExist) {
		log.Warnf("could not create %s qdisc to %d: %v", QdiscKind, ifindex, err)
		return err
	}
	flag := uint32(TcaBpfFlagActDiretct)
	// Attach ingress program
	if direction == "ingress" {
		filterIngress := tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: ifindex,
				Handle:  1,
				Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
				// Info definition and usage could be referred from net/sched/cls_api.c 'tc_new_tfilter'
				// higher 16bits are used as priority, lower 16bits are used as protocol
				// refer include/net/sch_generic.h
				// prio is define as 'u32' while protocol is '__be16'. :(
				Info: core.BuildHandle(uint32(TcPrioFilter), uint32(htons(unix.ETH_P_ALL))),
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &fd,
					Name:  &name,
					Flags: &flag,
				},
			},
		}
		if err := rtnl.Filter().Add(&filterIngress); err != nil && !errors.Is(err, os.ErrExist) {
			log.Warnf("could not attach ingress eBPF: %v\n", err)
			return err
		}
	}
	// Attach egress program
	if direction == "egress" {
		filterEgress := tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: ifindex,
				Handle:  1,
				Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
				Info:    core.BuildHandle(uint32(TcPrioFilter), uint32(htons(unix.ETH_P_ALL))),
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &fd,
					Name:  &name,
					Flags: &flag,
				},
			},
		}

		if err := rtnl.Filter().Add(&filterEgress); err != nil && !errors.Is(err, os.ErrExist) {
			log.Warnf("could not attach egress eBPF: %v", err)
			return err
		}
	}
	return nil
}

func htons(a uint16) uint16 {
	if isBigEndian {
		return a
	}
	return (a&0xff)<<8 | (a&0xff00)>>8
}
