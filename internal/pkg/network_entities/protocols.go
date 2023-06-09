package network_entities

var protocols []Protocol
var Protocols_map map[string]*Protocol
var tcp_ports []TcpPorts
var tcp_ports_map map[string]*TcpPorts
var icmp_type_codes []IcmpTypeCodes
var icmp_type_codes_map map[string]*IcmpTypeCodes

func init() {
	protocols = []Protocol{
		{0, "hopopt"},
		{1, "icmp"},
		{2, "igmp"},
		{3, "ggp"},
		{4, "ipv4"},
		{5, "st"},
		{6, "tcp"},
		{7, "cbt"},
		{8, "egp"},
		{9, "igp"},
		{10, "bbn-rcc-mon"},
		{11, "nvp-ii"},
		{12, "pup"},
		{13, "argus (deprecated)"},
		{14, "emcon"},
		{15, "xnet"},
		{16, "chaos"},
		{17, "udp"},
		{18, "mux"},
		{19, "dcn-meas"},
		{20, "hmp"},
		{21, "prm"},
		{22, "xns-idp"},
		{23, "trunk-1"},
		{24, "trunk-2"},
		{25, "leaf-1"},
		{26, "leaf-2"},
		{27, "rdp"},
		{28, "irtp"},
		{29, "iso-tp4"},
		{30, "netblt"},
		{31, "mfe-nsp"},
		{32, "merit-inp"},
		{33, "dccp"},
		{34, "3pc"},
		{35, "idpr"},
		{36, "xtp"},
		{37, "ddp"},
		{38, "idpr-cmtp"},
		{39, "tp++"},
		{40, "il"},
		{41, "ipv6"},
		{42, "sdrp"},
		{43, "ipv6-route"},
		{44, "ipv6-frag"},
		{45, "idrp"},
		{46, "rsvp"},
		{47, "gre"},
		{48, "dsr"},
		{49, "bna"},
		{50, "esp"},
		{51, "ah"},
		{52, "i-nlsp"},
		{53, "swipe (deprecated)"},
		{54, "narp"},
		{55, "mobile"},
		{56, "tlsp"},
		{57, "skip"},
		{58, "ipv6-icmp"},
		{59, "ipv6-nonxt"},
		{60, "ipv6-opts"},
		{62, "cftp"},
		{64, "sat-expak"},
		{65, "kryptolan"},
		{66, "rvd"},
		{67, "ippc"},
		{69, "sat-mon"},
		{70, "visa"},
		{71, "ipcv"},
		{72, "cpnx"},
		{73, "cphb"},
		{74, "wsn"},
		{75, "pvp"},
		{76, "br-sat-mon"},
		{77, "sun-nd"},
		{78, "wb-mon"},
		{79, "wb-expak"},
		{80, "iso-ip"},
		{81, "vmtp"},
		{82, "secure-vmtp"},
		{83, "vines"},
		{84, "iptm"},
		{85, "nsfnet-igp"},
		{86, "dgp"},
		{87, "tcf"},
		{88, "eigrp"},
		{89, "ospf"},
		{90, "sprite-rpc"},
		{91, "larp"},
		{92, "mtp"},
		{93, "ax.25"},
		{94, "ipip"},
		{95, "micp"},
		{96, "scc-sp"},
		{97, "etherip"},
		{98, "encap"},
		{100, "gmtp"},
		{101, "ifmp"},
		{102, "pnni"},
		{103, "pim"},
		{104, "aris"},
		{105, "scps"},
		{106, "qnx"},
		{107, "a/n"},
		{108, "ipcomp"},
		{109, "snp"},
		{110, "compaq-peer"},
		{111, "ipx-in-ip"},
		{112, "vrrp"},
		{113, "pgm"},
		{115, "l2tp"},
		{116, "ddx"},
		{117, "iatp"},
		{118, "stp"},
		{119, "srp"},
		{120, "uti"},
		{121, "smp"},
		{122, "sm"},
		{123, "ptp"},
		{124, "isis over ipv4"},
		{125, "fire"},
		{126, "crtp"},
		{127, "crudp"},
		{128, "sscopmce"},
		{129, "iplt"},
		{130, "sps"},
		{131, "pipe"},
		{132, "sctp"},
		{133, "fc"},
		{134, "rsvp-e2e-ignore"},
		{135, "mobility header"},
		{136, "udplite"},
		{137, "mpls-in-ip"},
		{138, "manet"},
		{139, "hip"},
		{140, "shim6"},
		{141, "wesp"},
		{142, "rohc"},
		{143, "ethernet"},
		{144, "aggfrag"},
		{255, "reserved"},
	}

	tcp_ports = []TcpPorts{
		{2049, "nfs"},
		{500, "isakmp"},
		{554, "rtsp"},
		{67, "bootps"},
		{68, "bootpc"},
		{69, "tftp"},
		{5632, "pcanywhere-status"},
		{514, "rsh"},
		{161, "snmp"},
		{162, "snmptrap"},
		{137, "netbios-ns"},
		{138, "netbios-dgm"},
		{1494, "citrix-ica"},
		{514, "syslog"},
		{5190, "aol"},
		{179, "bgp"},
		{19, "chargen"},
		{514, "cmd"},
		{2748, "ctiqbe"},
		{13, "daytime"},
		{9, "discard"},
		{53, "domain"},
		{7, "echo"},
		{512, "exec"},
		{79, "finger"},
		{21, "ftp"},
		{20, "ftp-data"},
		{70, "gopher"},
		{1720, "h323"},
		{101, "hostname"},
		{80, "http"},
		{443, "https"},
		{113, "ident"},
		{143, "imap4"},
		{194, "irc"},
		{750, "kerberos"},
		{543, "klogin"},
		{544, "kshell"},
		{389, "ldap"},
		{636, "ldaps"},
		{513, "login"},
		{1352, "lotusnotes"},
		{515, "lpd"},
		{139, "netbios-ssn"},
		{119, "nntp"},
		{123, "ntp"},
		{5631, "pcanywhere-data"},
		{496, "pim-auto-rp"},
		{109, "pop2"},
		{110, "pop3"},
		{1723, "pptp"},
		{25, "smtp"},
		{1521, "sqlnet"},
		{22, "ssh"},
		{111, "sunrpc"},
		{49, "tacacs"},
		{517, "talk"},
		{23, "telnet"},
		{540, "uucp"},
		{513, "whois"},
		{80, "www"},
		{5060, "sip"},
	}

	icmp_type_codes = []IcmpTypeCodes{
		{0, "echo-reply"},
		{3, "unreachable"},
		{4, "source-quench"},
		{5, "redirect"},
		{6, "alternate-address"},
		{8, "echo"},
		{9, "router-advertisement"},
		{10, "router-solicitation"},
		{11, "time-exceeded"},
		{12, "parameter-problem"},
		{13, "timestamp-request"},
		{14, "timestamp-reply"},
		{15, "information-request"},
		{16, "information-reply"},
		{17, "mask-request"},
		{18, "mask-reply"},
		{31, "conversion-error"},
		{32, "mobile-redirect"},
	}

	Protocols_map = make(map[string]*Protocol)
	for idx, proto := range protocols {
		Protocols_map[proto.Title] = &protocols[idx]
	}
	Protocols_map["ip"] = &protocols[4]

	tcp_ports_map = make(map[string]*TcpPorts)
	for idx, tcp_port := range tcp_ports {
		tcp_ports_map[tcp_port.Title] = &tcp_ports[idx]
	}

	icmp_type_codes_map = make(map[string]*IcmpTypeCodes)
	for idx, icmp_type_code := range icmp_type_codes {
		icmp_type_codes_map[icmp_type_code.Title] = &icmp_type_codes[idx]
	}

	// log.Println(Protocols_map["IPv4"].IsProtoMatch(Protocols_map["UDP"]))
	// log.Println(Protocols_map["UDP"].IsProtoMatch(Protocols_map["IPv4"]))
}

func (proto *Protocol) Match(proto2 *Protocol) bool {
	if proto.Id == proto2.Id {
		return true
	}
	if proto.Id == 4 { // IPv4
		return true
	}
	if proto2.Id == 4 { // IPv4
		return true
	}
	return false
}

func (proto *Protocol) ExactMatch(proto2 *Protocol) bool {
	if proto.Id == proto2.Id {
		return true
	}
	return false
}
