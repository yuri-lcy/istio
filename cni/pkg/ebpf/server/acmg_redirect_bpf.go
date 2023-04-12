package server

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type acmg_redirectAppInfo struct {
	Ifindex uint32
	MacAddr [6]uint8
	Pads    [2]uint8
}

type acmg_redirectHostInfo struct{ Addr [4]uint32 }

type acmg_redirectZtunnelInfo struct {
	Ifindex uint32
	MacAddr [6]uint8
	Flag    uint8
	Pad     uint8
}

// loadAcmg_redirect returns the embedded CollectionSpec for Acmg_redirect.
func loadAcmg_redirect() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Acmg_redirectBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Acmg_redirect: %w", err)
	}

	return spec, err
}

// loadAcmg_redirectObjects loads Acmg_redirect and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*Acmg_redirectObjects
//	*Acmg_redirectPrograms
//	*Acmg_redirectMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadAcmg_redirectObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadAcmg_redirect()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// acmg_redirectSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type acmg_redirectSpecs struct {
	acmg_redirectProgramSpecs
	acmg_redirectMapSpecs
}

// Acmg_redirectSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type acmg_redirectProgramSpecs struct {
	AppInbound         *ebpf.ProgramSpec `ebpf:"app_inbound"`
	AppOutbound        *ebpf.ProgramSpec `ebpf:"app_outbound"`
	ZtunnelHostIngress *ebpf.ProgramSpec `ebpf:"ztunnel_host_ingress"`
	ZtunnelIngress     *ebpf.ProgramSpec `ebpf:"ztunnel_ingress"`
}

// Acmg_redirectMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type acmg_redirectMapSpecs struct {
	AppInfo       *ebpf.MapSpec `ebpf:"app_info"`
	HostIpInfo    *ebpf.MapSpec `ebpf:"host_ip_info"`
	LogLevel      *ebpf.MapSpec `ebpf:"log_level"`
	NodeProxyInfo *ebpf.MapSpec `ebpf:"node_proxy_info"`
}

// Acmg_redirectObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadAcmg_redirectObjects or ebpf.CollectionSpec.LoadAndAssign.
type acmg_redirectObjects struct {
	acmg_redirectPrograms
	acmg_redirectMaps
}

func (o *acmg_redirectObjects) Close() error {
	return _Acmg_redirectClose(
		&o.acmg_redirectPrograms,
		&o.acmg_redirectMaps,
	)
}

// acmg_redirectMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadAcmg_redirectObjects or ebpf.CollectionSpec.LoadAndAssign.
type acmg_redirectMaps struct {
	AppInfo     *ebpf.Map `ebpf:"app_info"`
	HostIpInfo  *ebpf.Map `ebpf:"host_ip_info"`
	LogLevel    *ebpf.Map `ebpf:"log_level"`
	ZtunnelInfo *ebpf.Map `ebpf:"ztunnel_info"`
}

func (m *acmg_redirectMaps) Close() error {
	return _Acmg_redirectClose(
		m.AppInfo,
		m.HostIpInfo,
		m.LogLevel,
		m.ZtunnelInfo,
	)
}

// acmg_redirectPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadAcmg_redirectObjects or ebpf.CollectionSpec.LoadAndAssign.
type acmg_redirectPrograms struct {
	AppInbound           *ebpf.Program `ebpf:"app_inbound"`
	AppOutbound          *ebpf.Program `ebpf:"app_outbound"`
	NodeProxyHostIngress *ebpf.Program `ebpf:"node_proxy_host_ingress"`
	NodeProxyIngress     *ebpf.Program `ebpf:"node_proxy_ingress"`
}

func (p *acmg_redirectPrograms) Close() error {
	return _Acmg_redirectClose(
		p.AppInbound,
		p.AppOutbound,
		p.NodeProxyHostIngress,
		p.NodeProxyIngress,
	)
}

func _Acmg_redirectClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed acmg_redirect_bpf.o
var _Acmg_redirectBytes []byte
