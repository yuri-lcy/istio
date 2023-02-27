package constants

const (
	// In the below, we add the fwmask to ensure only that mark can match
	OutboundMask = "0x100"
	OutboundMark = OutboundMask + "/" + OutboundMask
	SkipMask     = "0x200"
	SkipMark     = SkipMask + "/" + SkipMask
	ConnSkipMask = "0x220"
	ConnSkipMark = ConnSkipMask + "/" + ConnSkipMask
	ProxyMask    = "0x210"
	ProxyMark    = ProxyMask + "/" + ProxyMask
	ProxyRetMask = "0x040"
	ProxyRetMark = ProxyRetMask + "/" + ProxyRetMask

	InboundTun  = "istioin"
	OutboundTun = "istioout"

	InboundTunIP           = "192.168.126.1"
	NodeProxyInboundTunIP  = "192.168.126.2"
	OutboundTunIP          = "192.168.127.1"
	NodeProxyOutboundTunIP = "192.168.127.2"
	TunPrefix              = 30

	ChainNodeProxyPrerouting  = "nodeproxy-PREROUTING"
	ChainNodeProxyPostrouting = "nodeproxy-POSTROUTING"
	ChainNodeProxyInput       = "nodeproxy-INPUT"
	ChainNodeProxyOutput      = "nodeproxy-OUTPUT"
	ChainNodeProxyForward     = "nodeproxy-FORWARD"

	ChainPrerouting  = "PREROUTING"
	ChainPostrouting = "POSTROUTING"
	ChainInput       = "INPUT"
	ChainOutput      = "OUTPUT"
	ChainForward     = "FORWARD"

	TableMangle = "mangle"
	TableNat    = "nat"
	TableRaw    = "raw"
	TableFilter = "filter"

	DNSCapturePort = 15053
)

const (
	RouteTableInbound  = 100
	RouteTableOutbound = 101
	RouteTableProxy    = 102
)

const (
	AcmgConfigFilepath = "/etc/acmg-config/config.json"
)
