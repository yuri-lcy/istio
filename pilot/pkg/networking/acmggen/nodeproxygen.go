package acmggen

import (
	"fmt"
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	fileaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	originaldst "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/original_dst/v3"
	originalsrc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/original_src/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	http "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	any "google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	wrappers "google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pilot/pkg/ambient"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/core/v1alpha3/match"
	"istio.io/istio/pilot/pkg/networking/plugin/authn"
	"istio.io/istio/pilot/pkg/networking/util"
	security "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pilot/pkg/util/protoconv"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/util/sets"
	"strconv"
	"time"
)

type NodeProxyConfigGenerator struct {
	EndpointIndex *model.EndpointIndex
	Workloads     acmg.AcmgCache
}

const (
	NodeProxyOutboundCapturePort       uint32 = 15001
	NodeProxyInbound2CapturePort       uint32 = 15006
	ZTunnelInboundNodeLocalCapturePort uint32 = 15088
	ZTunnelInboundCapturePort          uint32 = 15008

	// TODO: this needs to match the mark in the iptables rules.
	// And also not clash with any other mark on the host level.
	// either figure out a way to not hardcode it, or a way to not use it.
	// i think the best solution is to have this mark configurable and run the
	// iptables rules from the code, so we are sure the mark matches.
	OriginalSrcMark = 0x4d2
	OutboundMark    = 0x401
	InboundMark     = 0x402
)

// these exist on syscall package, but only on linux.
// copy these here so this file can build on any platform
const (
	SolSocket = 0x1
	SoMark    = 0x24
)

func buildCommonTLSContext(proxy *model.Proxy, workload *ambient.Workload, push *model.PushContext, inbound bool) *tls.CommonTlsContext {
	ctx := &tls.CommonTlsContext{}
	// TODO san match
	security.ApplyToCommonTLSContext(ctx, proxy, nil, authn.TrustDomainsForValidation(push.Mesh), inbound)

	// TODO always use the below flow, always specify which workload
	if workload != nil {
		// present the workload cert if possible
		workloadSecret := workload.Identity()
		if workload.UID != "" {
			workloadSecret += "~" + workload.Name + "~" + workload.UID
		}
		ctx.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
			security.ConstructSdsSecretConfig(workloadSecret),
		}
	}
	ctx.AlpnProtocols = []string{"h2"}

	ctx.TlsParams = &tls.TlsParameters{
		// Ensure TLS 1.3 is used everywhere
		TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
		TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_3,
	}

	return ctx
}

func h2connectUpgrade() map[string]*any.Any {
	return map[string]*any.Any{
		v3.HttpProtocolOptionsType: protoconv.MessageToAny(&http.HttpProtocolOptions{
			UpstreamProtocolOptions: &http.HttpProtocolOptions_ExplicitHttpConfig_{ExplicitHttpConfig: &http.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &http.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
					Http2ProtocolOptions: &core.Http2ProtocolOptions{
						AllowConnect: true,
					},
				},
			}},
		}),
	}
}

// outboundTunnelCluster is per-workload SA, but requires one workload that uses that SA so we can send the Pod UID
func outboundTunnelCluster(proxy *model.Proxy, push *model.PushContext, sa string, workload *ambient.Workload) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 outboundTunnelClusterName(sa),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
		LbPolicy:             cluster.Cluster_CLUSTER_PROVIDED,
		ConnectTimeout:       durationpb.New(2 * time.Second),
		CleanupInterval:      durationpb.New(60 * time.Second),
		LbConfig: &cluster.Cluster_OriginalDstLbConfig_{
			OriginalDstLbConfig: &cluster.Cluster_OriginalDstLbConfig{},
		},
		TypedExtensionProtocolOptions: h2connectUpgrade(),
		TransportSocket: &core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.UpstreamTlsContext{
				CommonTlsContext: buildCommonTLSContext(proxy, workload, push, false),
			})},
		},
	}
}

func ipPortAddress(ip string, port uint32) *core.Address {
	return &core.Address{Address: &core.Address_SocketAddress{
		SocketAddress: &core.SocketAddress{
			Address: ip,
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: port,
			},
		},
	}}
}

const EnvoyTextLogFormat = "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% " +
	"%PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% " +
	"%RESPONSE_CODE_DETAILS% %CONNECTION_TERMINATION_DETAILS% " +
	"\"%UPSTREAM_TRANSPORT_FAILURE_REASON%\" %BYTES_RECEIVED% %BYTES_SENT% " +
	"%DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" " +
	"\"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\" " +
	"%UPSTREAM_CLUSTER% %UPSTREAM_LOCAL_ADDRESS% %DOWNSTREAM_LOCAL_ADDRESS% " +
	"%DOWNSTREAM_REMOTE_ADDRESS% %REQUESTED_SERVER_NAME% %ROUTE_NAME% "

func accessLogString(prefix string) []*accesslog.AccessLog {
	inlineString := EnvoyTextLogFormat + prefix + "\n"
	return []*accesslog.AccessLog{{
		Name: "envoy.access_loggers.file",
		ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: protoconv.MessageToAny(&fileaccesslog.FileAccessLog{
			Path: "/dev/stdout",
			AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{LogFormat: &core.SubstitutionFormatString{
				Format: &core.SubstitutionFormatString_TextFormatSource{TextFormatSource: &core.DataSource{Specifier: &core.DataSource_InlineString{
					InlineString: inlineString,
				}}},
			}},
		})},
	}}
}

func outboundTunnelClusterName(sa string) string {
	return "outbound_tunnel_clus_" + sa
}

// outboundTunnelListener is built for each ServiceAccount from pods on the node.
// This listener adds the original destination headers from the dynamic EDS metadata pass through.
// We build the listener per-service account so that it can point to the corresponding cluster that presents the correct cert.
func outboundTunnelListener(name string, sa string) *discovery.Resource {
	l := &listener.Listener{
		Name:              name,
		UseOriginalDst:    wrappers.Bool(false),
		ListenerSpecifier: &listener.Listener_InternalListener{InternalListener: &listener.Listener_InternalListenerConfig{}},
		ListenerFilters:   []*listener.ListenerFilter{util.InternalListenerSetAddressFilter()},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: wellknown.TCPProxy,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
						StatPrefix:       name,
						AccessLog:        accessLogString("outbound tunnel"),
						ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: outboundTunnelClusterName(sa)},
						TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
							Hostname: "%DYNAMIC_METADATA(tunnel:destination)%",
							HeadersToAdd: []*core.HeaderValueOption{
								{Header: &core.HeaderValue{Key: "x-envoy-original-dst-host", Value: "%DYNAMIC_METADATA([\"tunnel\", \"destination\"])%"}},
							},
						},
					}),
				},
			}},
		}},
	}
	return &discovery.Resource{
		Name:     name,
		Resource: protoconv.MessageToAny(l),
	}
}

func passthroughFilterChain() *listener.FilterChain {
	return &listener.FilterChain{
		Name: util.PassthroughFilterChain,
		/// TODO no match – add one to make it so we only passthrough if strict mTLS to the destination is allowed
		Filters: []*listener.Filter{{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
				AccessLog:        accessLogString("passthrough"),
				StatPrefix:       util.PassthroughCluster,
				ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: util.PassthroughCluster},
			})},
		}},
	}
}

func buildCoreProxyLbEndpoints(t string, push *model.PushContext) []*endpoint.LocalityLbEndpoints {
	port := NodeProxyOutboundCapturePort
	if t == "server" {
		port = NodeProxyInbound2CapturePort
	}

	lbEndpoints := &endpoint.LocalityLbEndpoints{
		LbEndpoints: []*endpoint.LbEndpoint{},
	}
	for _, coreproxy := range push.AcmgIndex.CoreProxy.ByNamespacedName {
		lbEndpoints.LbEndpoints = append(lbEndpoints.LbEndpoints, &endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{
				Address: &core.Address{
					Address: &core.Address_SocketAddress{
						SocketAddress: &core.SocketAddress{
							Address:       coreproxy.PodIP,
							PortSpecifier: &core.SocketAddress_PortValue{PortValue: port},
						},
					},
				},
			}},
		})
	}
	return []*endpoint.LocalityLbEndpoints{lbEndpoints}
}

func buildCoreProxyChain(workload acmg.Workload) *listener.FilterChain {

	toCoreProxyCluster := toCoreProxyClusterName(workload.Identity())

	return &listener.FilterChain{
		Name: toCoreProxyCluster,
		Filters: []*listener.Filter{{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
				AccessLog:        accessLogString(fmt.Sprintf("capture outbound (%v to core proxy)", workload.Identity())),
				StatPrefix:       toCoreProxyCluster,
				ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: toCoreProxyCluster},
				TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
					Hostname: "%DOWNSTREAM_LOCAL_ADDRESS%", // (unused, per extended connect)
					HeadersToAdd: []*core.HeaderValueOption{
						// This is for server ztunnel - not really needed for waypoint proxy
						{Header: &core.HeaderValue{Key: "x-envoy-original-dst-host", Value: "%DOWNSTREAM_LOCAL_ADDRESS%"}},

						// This is for metadata propagation
						// TODO: should we just set the baggage directly, as we have access to the Pod here (instead of using the filter)?
						{Header: &core.HeaderValue{Key: "baggage", Value: "%DYNAMIC_METADATA([\"envoy.filters.listener.workload_metadata\", \"baggage\"])%"}},
					},
				},
			},
			)},
		}},
	}
}

func blackholeFilterChain(t string) *listener.FilterChain {
	return &listener.FilterChain{
		Name: "blackhole " + t,
		Filters: []*listener.Filter{{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
				AccessLog:        accessLogString("blackhole " + t),
				StatPrefix:       util.BlackHoleCluster,
				ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: "blackhole " + t},
			})},
		}},
	}
}

func toCoreProxyClusterName(workloadIdentity string) string {
	return fmt.Sprintf("%s_to_server_core_proxy", workloadIdentity)
}

// buildPodOutboundCaptureListener creates a single listener with a FilterChain for each combination
// of ServiceAccount from pods on the node and Service VIP in the cluster.
func (g *NodeProxyConfigGenerator) buildPodOutboundCaptureListener(proxy *model.Proxy, push *model.PushContext) *discovery.Resource {
	l := &listener.Listener{
		Name:           "nodeproxy_outbound",
		UseOriginalDst: wrappers.Bool(true),
		Transparent:    wrappers.Bool(true),
		AccessLog:      accessLogString("outbound capture listener"),
		SocketOptions: []*core.SocketOption{{
			Description: "Set socket mark to packets coming back from outbound listener",
			Level:       SolSocket,
			Name:        SoMark,
			Value: &core.SocketOption_IntValue{
				IntValue: OutboundMark,
			},
			State: core.SocketOption_STATE_PREBIND,
		}},
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name: wellknown.OriginalDestination,
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&originaldst.OriginalDst{}),
				},
			},
		},
		Address: &core.Address{Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Address: "0.0.0.0",
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: NodeProxyOutboundCapturePort,
				},
			},
		}},
	}
	if push.Mesh.GetOutboundTrafficPolicy().GetMode() == v1alpha1.MeshConfig_OutboundTrafficPolicy_ALLOW_ANY {
		l.DefaultFilterChain = passthroughFilterChain()
	}
	// nolint: gocritic
	// if features.SidecarlessCapture == model.VariantIptables {
	l.ListenerFilters = append(l.ListenerFilters, &listener.ListenerFilter{
		Name: wellknown.OriginalSource,
		ConfigType: &listener.ListenerFilter_TypedConfig{
			TypedConfig: protoconv.MessageToAny(&originalsrc.OriginalSrc{
				Mark: OriginalSrcMark,
			}),
		},
	})
	//}

	l.ListenerFilters = append(l.ListenerFilters, &listener.ListenerFilter{
		Name: WorkloadMetadataListenerFilterName,
		ConfigType: &listener.ListenerFilter_ConfigDiscovery{
			ConfigDiscovery: &core.ExtensionConfigSource{
				ConfigSource: &core.ConfigSource{
					ConfigSourceSpecifier: &core.ConfigSource_Ads{Ads: &core.AggregatedConfigSource{}},
					InitialFetchTimeout:   durationpb.New(30 * time.Second),
				},
				TypeUrls: []string{WorkloadMetadataResourcesTypeURL},
			},
		},
	})

	// match logic:
	// dest port == 15001 -> blackhole
	// source unknown -> passthrough
	// source known, -> coreproxy
	sourceMatch := match.NewSourceIP()
	sourceMatch.OnNoMatch = match.ToChain(util.PassthroughFilterChain)

	destPortMatch := match.NewDestinationPort()
	destPortMatch.OnNoMatch = match.ToMatcher(sourceMatch.Matcher)
	destPortMatch.Map[strconv.Itoa(int(l.GetAddress().GetSocketAddress().GetPortValue()))] = match.ToChain(util.BlackHoleCluster)

	seen := sets.String{}
	// 这里从workload cache中取出的workload确保了全部是acmg范围内的
	for _, sourceWl := range push.AcmgIndex.Workloads.NodeLocal(proxy.Metadata.NodeName) {
		chain := buildCoreProxyChain(sourceWl)
		sourceMatch.Map[sourceWl.PodIP] = match.ToChain(chain.Name)
		if !seen.InsertContains(chain.Name) {
			l.FilterChains = append(l.FilterChains, chain)
		}
	}

	l.FilterChainMatcher = destPortMatch.BuildMatcher()
	l.FilterChains = append(l.FilterChains, passthroughFilterChain(), blackholeFilterChain("outbound"))
	return &discovery.Resource{
		Name:     l.Name,
		Resource: protoconv.MessageToAny(l),
	}
}
