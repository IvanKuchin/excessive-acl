package ciscoasaaccessentry

import (
	"testing"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func Test_accessEntryCompiled_MatchFlow(t *testing.T) {
	type args struct {
		flow network_entities.Flow
	}
	tests := []struct {
		name    string
		ace     *accessEntryCompiled
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "ACL-IP and TCP-flow",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 4, Title: "ipv4"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				src_port_range: port_range{0, 0},
				dst_port_range: port_range{0, 0},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			args: args{
				flow: network_entities.Flow{
					Protocol: &network_entities.Protocol{Id: 6, Title: "tcp"},
					Src_ip:   0x01020304,
					Dst_ip:   0x0a0a0a0a,
					Src_port: 1024,
					Dst_port: 22,
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ACL-TCP and TCP-flow",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 6, Title: "tcp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				src_port_range: port_range{1024, 1025},
				dst_port_range: port_range{22, 22},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			args: args{
				flow: network_entities.Flow{
					Protocol: &network_entities.Protocol{Id: 6, Title: "tcp"},
					Src_ip:   0x01020304,
					Dst_ip:   0x0a0a0a0a,
					Src_port: 1024,
					Dst_port: 22,
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ACL-ICMP and ICMP-flow",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 1, Title: "icmp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			args: args{
				flow: network_entities.Flow{
					Protocol:  &network_entities.Protocol{Id: 1, Title: "icmp"},
					Src_ip:    0x01020304,
					Dst_ip:    0x0a0a0a0a,
					Icmp_type: 0,
					Icmp_code: 0,
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ACL-ICMP type and ICMP-flow",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 1, Title: "icmp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				icmp:           icmp_type_code{icmp_type: 0, icmp_code: -1},
			},
			args: args{
				flow: network_entities.Flow{
					Protocol:  &network_entities.Protocol{Id: 1, Title: "icmp"},
					Src_ip:    0x01020304,
					Dst_ip:    0x0a0a0a0a,
					Icmp_type: 0,
					Icmp_code: 0,
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ACL-ICMP type code and ICMP-flow",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 1, Title: "icmp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				icmp:           icmp_type_code{icmp_type: 0, icmp_code: 0},
			},
			args: args{
				flow: network_entities.Flow{
					Protocol:  &network_entities.Protocol{Id: 1, Title: "icmp"},
					Src_ip:    0x01020304,
					Dst_ip:    0x0a0a0a0a,
					Icmp_type: 0,
					Icmp_code: 0,
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "no match: ACL-TCP and TCP-flow",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 6, Title: "tcp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				src_port_range: port_range{1, 65535},
				dst_port_range: port_range{22, 22},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			args: args{
				flow: network_entities.Flow{
					Protocol: &network_entities.Protocol{Id: 6, Title: "tcp"},
					Src_ip:   0x01020304,
					Dst_ip:   0x0a0a0a0a,
					Src_port: 1024,
					Dst_port: 23,
				},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "no match: ACL-TCP and UDP-flow",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 6, Title: "tcp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				src_port_range: port_range{1, 65535},
				dst_port_range: port_range{22, 22},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			args: args{
				flow: network_entities.Flow{
					Protocol: &network_entities.Protocol{Id: 16, Title: "udp"},
					Src_ip:   0x01020304,
					Dst_ip:   0x0a0a0a0a,
					Src_port: 1024,
					Dst_port: 22,
				},
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ace.MatchFlow(tt.args.flow)
			if (err != nil) != tt.wantErr {
				t.Errorf("accessEntryCompiled.MatchFlow() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("accessEntryCompiled.MatchFlow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_accessEntryCompiled_getCapacity(t *testing.T) {
	tests := []struct {
		name    string
		ace     *accessEntryCompiled
		want    uint
		wantErr bool
	}{
		{
			name: "TCP single dst port",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 6, Title: "tcp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				src_port_range: port_range{0, 0},
				dst_port_range: port_range{22, 22},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			want:    (0x1) * 1 * 0x1 * 1,
			wantErr: false,
		},
		{
			name: "TCP two dst ports",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 6, Title: "tcp"},
				src_addr_range: utils.AddressObject{Start: 0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				src_port_range: port_range{0, 0},
				dst_port_range: port_range{22, 23},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			want:    (0x1) * 1 * 0x1 * 2,
			wantErr: false,
		},
		{
			name: "ICMP no type no code",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 1, Title: "icmp"},
				src_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			want:    1 * 1 * 256 * 256,
			wantErr: false,
		},
		{
			name: "ICMP one type no code",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 1, Title: "icmp"},
				src_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				icmp:           icmp_type_code{icmp_type: 8, icmp_code: -1},
			},
			want:    1 * 1 * 1 * 256,
			wantErr: false,
		},
		{
			name: "ICMP one type one code",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 1, Title: "icmp"},
				src_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				icmp:           icmp_type_code{icmp_type: 8, icmp_code: 0},
			},
			want:    1 * 1 * 1 * 1,
			wantErr: false,
		},
		{
			name: "IP single src, single dst",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 4, Title: "ipv4"},
				src_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				src_port_range: port_range{0, 0},
				dst_port_range: port_range{0, 0},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			want:    (0x0 + 1) * (0x0 + 1),
			wantErr: false,
		},
		{
			name: "TCP empty dst port range",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 6, Title: "tcp"},
				src_addr_range: utils.AddressObject{Start: 0x0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				dst_port_range: port_range{0, 0},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			want:    0x1 * 0x1 * 0x10000,
			wantErr: false,
		},
		{
			name: "IP src any",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 4, Title: "ipv4"},
				src_addr_range: utils.AddressObject{Start: 0x0, Finish: 0xffffffff},
				dst_addr_range: utils.AddressObject{Start: 0x0a0a0a0a, Finish: 0x0a0a0a0a},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			want:    0x1 * 0x1,
			wantErr: false,
		},
		{
			name: "zero flows",
			ace: &accessEntryCompiled{
				action:         permit,
				proto:          &network_entities.Protocol{Id: 4, Title: "ipv4"},
				src_addr_range: utils.AddressObject{Start: 0x1, Finish: 0x0},
				dst_addr_range: utils.AddressObject{Start: 0x1, Finish: 0x0},
				icmp:           icmp_type_code{icmp_type: -1, icmp_code: -1},
			},
			want:    0x0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ace.getCapacity()
			if (err != nil) != tt.wantErr {
				t.Errorf("accessEntryCompiled.calculateCoveredSpace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("accessEntryCompiled.calculateCoveredSpace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_accessEntryCompiled_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		ace     *accessEntryCompiled
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.ace.Analyze(); (err != nil) != tt.wantErr {
				t.Errorf("accessEntryCompiled.Analyze() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
