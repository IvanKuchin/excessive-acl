package network_entities

type Protocol struct {
	Id    uint
	Title string
}

type TcpPorts struct {
	Id    uint
	Title string
}

type IcmpTypeCodes struct {
	Id    uint
	Title string
}

type Flow struct {
	Src_iface string
	Dst_iface string
	Protocol  *Protocol
	Src_ip    uint32
	Dst_ip    uint32
	Src_port  uint16
	Dst_port  uint16
	Icmp_code int
	Icmp_type int
}
