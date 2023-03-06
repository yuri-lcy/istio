package v1alpha3

import (
	"fmt"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	wrappers "google.golang.org/protobuf/types/known/wrapperspb"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	istionetworking "istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/core/v1alpha3/match"
	"istio.io/istio/pilot/pkg/networking/plugin/authn"
	"istio.io/istio/pilot/pkg/networking/util"
	istiomatcher "istio.io/istio/pilot/pkg/security/authz/matcher"
	security "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pilot/pkg/util/protoconv"
	xdsfilters "istio.io/istio/pilot/pkg/xds/filters"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/proto"
	"istio.io/pkg/log"
	"strconv"
)

type LabeledWorkloadAndServices struct {
	WorkloadInfo acmg.Workload
	Services     []*model.Service
}

func getPorts(services []*model.ServiceInstance) []model.Port {
	p := map[int]model.Port{}
	for _, s := range services {
		p[int(s.Endpoint.EndpointPort)] = model.Port{
			Port:     int(s.Endpoint.EndpointPort),
			Protocol: s.ServicePort.Protocol,
		}
	}
	pl := []model.Port{}
	for _, m := range p {
		pl = append(pl, m)
	}
	return pl
}

func FindAllResources(push *model.PushContext) ([]LabeledWorkloadAndServices, map[host.Name]*model.Service) {
	var wls []LabeledWorkloadAndServices
	for _, wl := range push.AcmgIndex.Workloads.ByNamespacedName {
		if wl.Labels[acmg.LabelType] != acmg.TypeWorkload {
			continue
		}
		wls = append(wls, LabeledWorkloadAndServices{WorkloadInfo: wl})
	}
	svcs := map[host.Name]*model.Service{}
	for i, wl := range wls {
		for _, ns := range push.ServiceIndex.HostnameAndNamespace {
			svc := ns[wl.WorkloadInfo.Namespace]
			if svc == nil || len(svc.Attributes.LabelSelectors) == 0 {
				continue
			}
			if labels.Instance(svc.Attributes.LabelSelectors).SubsetOf(wl.WorkloadInfo.Labels) {
				svcs[svc.Hostname] = svc
				wl.Services = append(wl.Services, svc)
			}
		}
		wls[i] = wl
	}
	return wls, svcs
}

func (lb *ListenerBuilder) buildCoreProxyInbound() []*listener.Listener {
	log.Infof("buildCoreProxyInbound for coreproxy")
	listeners := []*listener.Listener{}
	// We create 4 listeners:
	// 1. Our top level terminating CONNECT listener, `inbound TERMINATE`. This has a route per destination and decapsulates the CONNECT,
	//    forwarding to the VIP or Pod internal listener.
	// 2. (many) VIP listeners, `inbound-vip||hostname|port`. This will apply service policies. For typical case (not redirecting to external service),
	//    this will end up forwarding to a cluster for the same VIP, which will have endpoints for each Pod internal listener
	// 3. (many) Pod listener, `inbound-pod||podip|port`. This is one per inbound pod. Will go through HCM if needed, in order to apply L7 policies (authz)
	//    Note: we need both a pod listener and a VIP listener since we need to apply policies at different levels (routing vs authz).
	// 4. Our final CONNECT listener, originating the tunnel
	wls, svcs := FindAllResources(lb.push)

	listeners = append(listeners, lb.buildCoreProxyInboundTerminateConnect(svcs, wls))

	// VIP listeners
	listeners = append(listeners, lb.buildCoreProxyInboundVIP(svcs)...)

	// Pod listeners
	listeners = append(listeners, lb.buildCoreProxyInboundPod(wls)...)

	listeners = append(listeners, lb.buildCoreProxyInboundOriginateConnect())

	return listeners
}

func (lb *ListenerBuilder) buildCoreProxyInboundOriginateConnect() *listener.Listener {
	name := "inbound_CONNECT_originate"
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
						ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: name},
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
	return l
}

// (many) Pod listener, `inbound||podip|port`. This is one per inbound pod. Will go through HCM if needed, in order to apply L7 policies (authz)
// Note: we need both a pod listener and a VIP listener since we need to apply policies at different levels (routing vs authz).
func (lb *ListenerBuilder) buildCoreProxyInboundPod(wls []LabeledWorkloadAndServices) []*listener.Listener {
	listeners := []*listener.Listener{}
	for _, wlx := range wls {
		// Follow same logic as today, but no mTLS ever
		wl := wlx.WorkloadInfo

		// For each port, setup a match
		// TODO: fake proxy is really bad. Should have these take in Workload or similar
		instances := lb.Discovery.GetProxyServiceInstances(&model.Proxy{
			Type:            model.SidecarProxy,
			IPAddresses:     []string{wl.PodIP},
			ConfigNamespace: wl.Namespace,
			Metadata: &model.NodeMetadata{
				Namespace: wl.Namespace,
				Labels:    wl.Labels,
			},
		})
		if len(instances) == 0 {
			// TODO: Don't we need some passthrough mechanism? We will need ORIG_PORT but custom IP to implement that though
			continue
		}
		wlBuilder := lb.WithAcmgWorkload(wl)
		for _, port := range getPorts(instances) {
			if port.Protocol == protocol.UDP {
				continue
			}
			cc := inboundChainConfig{
				clusterName: model.BuildSubsetKey(model.TrafficDirectionInboundPod, "", host.Name(wl.PodIP), port.Port),
				port: ServiceInstancePort{
					Name:       port.Name,
					Port:       uint32(port.Port),
					TargetPort: uint32(port.Port),
					Protocol:   port.Protocol,
				},
				bind:  "0.0.0.0",
				hbone: true,
			}
			name := cc.clusterName

			tcpName := name + "-tcp"
			tcpChain := &listener.FilterChain{
				Filters: wlBuilder.buildInboundNetworkFilters(cc),
				Name:    tcpName,
			}

			httpName := name + "-http"
			httpChain := &listener.FilterChain{
				Filters: wlBuilder.buildInboundNetworkFiltersForHTTP(cc),
				Name:    httpName,
			}
			l := &listener.Listener{
				Name:              name,
				ListenerSpecifier: &listener.Listener_InternalListener{InternalListener: &listener.Listener_InternalListenerConfig{}},
				ListenerFilters:   []*listener.ListenerFilter{util.InternalListenerSetAddressFilter()},
				TrafficDirection:  core.TrafficDirection_INBOUND,
				FilterChains:      []*listener.FilterChain{},
			}
			if port.Protocol.IsUnsupported() {
				// If we need to sniff, insert two chains and the protocol detector
				l.FilterChains = append(l.FilterChains, tcpChain, httpChain)
				l.FilterChainMatcher = match.NewAppProtocol(match.ProtocolMatch{
					TCP:  match.ToChain(tcpName),
					HTTP: match.ToChain(httpName),
				})
			} else if port.Protocol.IsHTTP() {
				// Otherwise, just insert HTTP/TCP
				l.FilterChains = append(l.FilterChains, httpChain)
			} else {
				l.FilterChains = append(l.FilterChains, tcpChain)
			}
			listeners = append(listeners, l)
		}
	}
	return listeners
}

func (lb *ListenerBuilder) coreproxyInboundRoute(virtualService config.Config, listenPort int) ([]*route.Route, error) {
	vs, ok := virtualService.Spec.(*networking.VirtualService)
	if !ok { // should never happen
		return nil, fmt.Errorf("in not a virtual service: %#v", virtualService)
	}

	out := make([]*route.Route, 0, len(vs.Http))

	catchall := false
	for _, http := range vs.Http {
		if len(http.Match) == 0 {
			if r := lb.translateRoute(virtualService, http, nil, listenPort); r != nil {
				out = append(out, r)
			}
			catchall = true
		} else {
			for _, match := range http.Match {
				if r := lb.translateRoute(virtualService, http, match, listenPort); r != nil {
					out = append(out, r)
					// This is a catch all path. Routes are matched in order, so we will never go beyond this match
					// As an optimization, we can just top sending any more routes here.
					//if isCatchAllMatch(match) {
					//	catchall = true
					//	break
					//}
				}
			}
		}
		if catchall {
			break
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no routes matched")
	}
	return out, nil
}

func buildCoreProxyInboundHTTPRouteConfig(lb *ListenerBuilder, svc *model.Service, cc inboundChainConfig) *route.RouteConfiguration {
	vss := getConfigsForHost(svc.Hostname, lb.node.SidecarScope.EgressListeners[0].VirtualServices())
	if len(vss) == 0 {
		return buildSidecarInboundHTTPRouteConfig(lb, cc)
	}
	if len(vss) > 1 {
		log.Warnf("multiple virtual services for one service: %v", svc.Hostname)
	}
	vs := vss[0]

	// Typically we setup routes with the Host header match. However, for coreproxy inbound we are actually using
	// hostname purely to match to the Service VIP. So we only need a single VHost, with routes compute based on the VS.
	// For destinations, we need to hit the inbound clusters if it is an internal destination, otherwise outbound.
	routes, err := lb.coreproxyInboundRoute(vs, int(cc.port.Port))
	if err != nil {
		return buildSidecarInboundHTTPRouteConfig(lb, cc)
	}

	inboundVHost := &route.VirtualHost{
		Name:    inboundVirtualHostPrefix + strconv.Itoa(int(cc.port.Port)), // Format: "inbound|http|%d"
		Domains: []string{"*"},
		Routes:  routes,
	}

	return &route.RouteConfiguration{
		Name:             cc.clusterName,
		VirtualHosts:     []*route.VirtualHost{inboundVHost},
		ValidateClusters: proto.BoolFalse,
	}
}

func (lb *ListenerBuilder) buildCoreProxyInboundVIPHTTPFilters(svc *model.Service, cc inboundChainConfig) []*listener.Filter {
	var filters []*listener.Filter
	if !lb.node.IsAcmg() {
		filters = append(filters, buildMetadataExchangeNetworkFilters(istionetworking.ListenerClassSidecarInbound)...)
	}

	httpOpts := &httpListenerOpts{
		routeConfig:      buildCoreProxyInboundHTTPRouteConfig(lb, svc, cc),
		rds:              "", // no RDS for inbound traffic
		useRemoteAddress: false,
		connectionManager: &hcm.HttpConnectionManager{
			// Append and forward client cert to backend.
			ForwardClientCertDetails: hcm.HttpConnectionManager_APPEND_FORWARD,
			SetCurrentClientCertDetails: &hcm.HttpConnectionManager_SetCurrentClientCertDetails{
				Subject: proto.BoolTrue,
				Uri:     true,
				Dns:     true,
			},
			ServerName: EnvoyServerName,
		},
		protocol:   cc.port.Protocol,
		class:      istionetworking.ListenerClassSidecarInbound,
		statPrefix: cc.StatPrefix(),

		skipTelemetryFilters: true, // do not include telemetry filters on the CONNECT termination chain
		skipRBACFilters:      true, // Handled by pod listener
	}
	// See https://github.com/grpc/grpc-web/tree/master/net/grpc/gateway/examples/helloworld#configure-the-proxy
	if cc.port.Protocol.IsHTTP2() {
		httpOpts.connectionManager.Http2ProtocolOptions = &core.Http2ProtocolOptions{}
	}

	if features.HTTP10 || enableHTTP10(lb.node.Metadata.HTTP10) {
		httpOpts.connectionManager.HttpProtocolOptions = &core.Http1ProtocolOptions{
			AcceptHttp_10: true,
		}
	}
	h := lb.buildHTTPConnectionManager(httpOpts)

	if lb.node.IsCoreProxy() {
		restoreTLSFilter := &listener.Filter{
			Name: "restore_tls",
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: protoconv.TypedStruct("type.googleapis.com/istio.tls_passthrough.v1.RestoreTLS"),
			},
		}
		filters = append(filters, restoreTLSFilter)
	}

	filters = append(filters, &listener.Filter{
		Name:       wellknown.HTTPConnectionManager,
		ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(h)},
	})
	return filters
}

// VIP listeners, `inbound||hostname|port`. This will apply service policies. For typical case (not redirecting to external service),
// this will end up forwarding to a cluster for the same VIP, which will have endpoints for each Pod internal listener
func (lb *ListenerBuilder) buildCoreProxyInboundVIP(svcs map[host.Name]*model.Service) []*listener.Listener {
	listeners := []*listener.Listener{}
	for _, svc := range svcs {
		for _, port := range svc.Ports {
			if port.Protocol == protocol.UDP {
				continue
			}
			cc := inboundChainConfig{
				clusterName: model.BuildSubsetKey(model.TrafficDirectionInboundVIP, "tcp", svc.Hostname, port.Port),
				port: ServiceInstancePort{
					Name:       port.Name,
					Port:       uint32(port.Port),
					TargetPort: uint32(port.Port),
					Protocol:   port.Protocol,
				},
				bind:  "0.0.0.0",
				hbone: true,
			}
			name := model.BuildSubsetKey(model.TrafficDirectionInboundVIP, "", svc.Hostname, port.Port)
			tcpName := name + "-tcp"
			tcpChain := &listener.FilterChain{
				Filters: lb.buildInboundNetworkFilters(cc),
				Name:    tcpName,
			}
			cc.clusterName = model.BuildSubsetKey(model.TrafficDirectionInboundVIP, "http", svc.Hostname, port.Port)
			httpName := name + "-http"
			httpChain := &listener.FilterChain{
				Filters: lb.buildCoreProxyInboundVIPHTTPFilters(svc, cc),
				Name:    httpName,
			}
			l := &listener.Listener{
				Name:              name,
				ListenerSpecifier: &listener.Listener_InternalListener{InternalListener: &listener.Listener_InternalListenerConfig{}},
				TrafficDirection:  core.TrafficDirection_INBOUND,
				FilterChains:      []*listener.FilterChain{},
				ListenerFilters: []*listener.ListenerFilter{
					util.InternalListenerSetAddressFilter(),
					{
						Name:       "envoy.filters.listener.metadata_to_peer_node",
						ConfigType: &listener.ListenerFilter_TypedConfig{TypedConfig: protoconv.TypedStruct("type.googleapis.com/istio.telemetry.metadatatopeernode.v1.Config")},
					},
				},
			}
			if port.Protocol.IsUnsupported() {
				// If we need to sniff, insert two chains and the protocol detector
				l.FilterChains = append(l.FilterChains, tcpChain, httpChain)
				l.FilterChainMatcher = match.NewAppProtocol(match.ProtocolMatch{
					TCP:  match.ToChain(tcpName),
					HTTP: match.ToChain(httpName),
				})
			} else if port.Protocol.IsHTTP() {
				// Otherwise, just insert HTTP/TCP
				l.FilterChains = append(l.FilterChains, httpChain)
			} else {
				l.FilterChains = append(l.FilterChains, tcpChain)
			}
			listeners = append(listeners, l)
		}
	}
	return listeners
}

func buildAcmgCommonTLSContext(proxy *model.Proxy, workload *acmg.Workload, push *model.PushContext, inbound bool) *tls.CommonTlsContext {
	ctx := &tls.CommonTlsContext{}
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

// Our top level terminating CONNECT listener, `inbound TERMINATE`. This has a route per destination and decapsulates the CONNECT,
// forwarding to the VIP or Pod internal listener.
func (lb *ListenerBuilder) buildCoreProxyInboundTerminateConnect(svcs map[host.Name]*model.Service, wls []LabeledWorkloadAndServices) *listener.Listener {
	actualWildcard, _ := getActualWildcardAndLocalHost(lb.node)
	// CONNECT listener
	vhost := &route.VirtualHost{
		Name:    "connect",
		Domains: []string{"*"},
	}
	for _, svc := range svcs {
		for _, port := range svc.Ports {
			if port.Protocol == protocol.UDP {
				continue
			}
			clusterName := model.BuildSubsetKey(model.TrafficDirectionInboundVIP, "internal", svc.Hostname, port.Port)
			vhost.Routes = append(vhost.Routes, &route.Route{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_ConnectMatcher_{ConnectMatcher: &route.RouteMatch_ConnectMatcher{}},
					Headers: []*route.HeaderMatcher{
						istiomatcher.HeaderMatcher(":authority", fmt.Sprintf("%s:%d", svc.GetAddressForProxy(lb.node), port.Port)),
					},
				},
				Action: &route.Route_Route{Route: &route.RouteAction{
					UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
						UpgradeType:   "CONNECT",
						ConnectConfig: &route.RouteAction_UpgradeConfig_ConnectConfig{},
					}},
					ClusterSpecifier: &route.RouteAction_Cluster{Cluster: clusterName},
				}},
			})
		}
	}

	// it's possible for us to hit this listener and target a Pod directly; route through the inbound-pod internal listener
	// TODO: this shouldn't match on port; we should accept traffic to any port.
	for _, wlx := range wls {
		wl := wlx.WorkloadInfo
		// TODO: fake proxy is really bad. Should have these take in Workload or similar
		instances := lb.Discovery.GetProxyServiceInstances(&model.Proxy{
			Type:            model.SidecarProxy,
			IPAddresses:     []string{wl.PodIP},
			ConfigNamespace: wl.Namespace,
			Metadata: &model.NodeMetadata{
				Namespace: wl.Namespace,
				Labels:    wl.Labels,
			},
		})
		// For each port, setup a route
		for _, port := range getPorts(instances) {
			clusterName := model.BuildSubsetKey(model.TrafficDirectionInboundPod, "internal", host.Name(wl.PodIP), port.Port)
			vhost.Routes = append(vhost.Routes, &route.Route{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_ConnectMatcher_{ConnectMatcher: &route.RouteMatch_ConnectMatcher{}},
					Headers: []*route.HeaderMatcher{
						istiomatcher.HeaderMatcher(":authority", fmt.Sprintf("%s:%d", wl.PodIP, port.Port)),
					},
				},
				Action: &route.Route_Route{Route: &route.RouteAction{
					UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
						UpgradeType:   "CONNECT",
						ConnectConfig: &route.RouteAction_UpgradeConfig_ConnectConfig{},
					}},
					ClusterSpecifier: &route.RouteAction_Cluster{Cluster: clusterName},
				}},
			})
		}
	}

	httpOpts := &httpListenerOpts{
		routeConfig: &route.RouteConfiguration{
			Name:             "local_route",
			VirtualHosts:     []*route.VirtualHost{vhost},
			ValidateClusters: proto.BoolFalse,
		},
		statPrefix:           "inbound_hcm",
		protocol:             protocol.HTTP2,
		class:                istionetworking.ListenerClassSidecarInbound,
		skipTelemetryFilters: true, // do not include telemetry filters on the CONNECT termination chain
		skipRBACFilters:      true,
	}

	h := lb.buildHTTPConnectionManager(httpOpts)

	h.HttpFilters = append([]*hcm.HttpFilter{xdsfilters.BaggageFilter}, h.HttpFilters...)
	h.UpgradeConfigs = []*hcm.HttpConnectionManager_UpgradeConfig{{
		UpgradeType: "CONNECT",
	}}
	h.Http2ProtocolOptions = &core.Http2ProtocolOptions{
		AllowConnect: true,
	}
	name := "inbound_CONNECT_terminate"
	l := &listener.Listener{
		Name:    name,
		Address: util.BuildAddress(actualWildcard, 15006),
		FilterChains: []*listener.FilterChain{
			{
				Name: name,
				TransportSocket: &core.TransportSocket{
					Name: "envoy.transport_sockets.tls",
					ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.DownstreamTlsContext{
						CommonTlsContext: buildAcmgCommonTLSContext(lb.node, nil, lb.push, true),
					})},
				},
				Filters: []*listener.Filter{
					xdsfilters.CaptureTLSFilter,
					{
						Name:       wellknown.HTTPConnectionManager,
						ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(h)},
					},
				},
			},
		},
	}
	return l
}
