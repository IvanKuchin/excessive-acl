package ciscoasaaccessentry

import (
	"reflect"
	"testing"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list/sh-run-pipe"
	"github.com/ivankuchin/excessive-acl/internal/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/utils"
)

func TestParse(t *testing.T) {
	type args struct {
		ace_text string
	}
	tests := []struct {
		name    string
		args    args
		want    AccessEntry
		wantErr bool
	}{
		{
			name: "icmp host 10.11.12.13 any4 log",
			args: args{
				ace_text: "access-list inside_in extended permit icmp host 10.11.12.13 any4 log",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit icmp host 10.11.12.13 any4 log",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    1,
							Title: "icmp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0b0c0d,
							Finish: 0x0a0b0c0d,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x00000000,
							Finish: 0xffffffff,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "icmp host 10.11.12.13 any4 echo log",
			args: args{
				ace_text: "access-list inside_in extended permit icmp host 10.11.12.13 any4 echo log",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit icmp host 10.11.12.13 any4 echo log",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    1,
							Title: "icmp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0b0c0d,
							Finish: 0x0a0b0c0d,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x00000000,
							Finish: 0xffffffff,
						},
						icmp: icmp_type_code{8, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ip host 10.11.12.13 any4",
			args: args{
				ace_text: "access-list inside_in extended permit ip host 10.11.12.13 any4",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit ip host 10.11.12.13 any4",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    4,
							Title: "ipv4",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0b0c0d,
							Finish: 0x0a0b0c0d,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x00000000,
							Finish: 0xffffffff,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "tcp host 10.10.10.10 host 10.10.10.1",
			args: args{
				ace_text: "access-list inside_in extended permit tcp host 10.10.10.10 host 10.10.10.1",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit tcp host 10.10.10.10 host 10.10.10.1",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    6,
							Title: "tcp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "udp host 10.10.10.10 eq ntp host 10.10.10.1 eq ntp",
			args: args{
				ace_text: "access-list inside_in extended permit udp host 10.10.10.10 eq ntp host 10.10.10.1 eq ntp",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit udp host 10.10.10.10 eq ntp host 10.10.10.1 eq ntp",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    17,
							Title: "udp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						src_port_range: port_range{
							start:  123,
							finish: 123,
						},
						dst_port_range: port_range{
							start:  123,
							finish: 123,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "tcp host 10.10.10.10 gt 1023 host 10.10.10.1 range 20 21",
			args: args{
				ace_text: "access-list inside_in extended permit tcp host 10.10.10.10 gt 1023 host 10.10.10.1 range 20 21",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit tcp host 10.10.10.10 gt 1023 host 10.10.10.1 range 20 21",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    6,
							Title: "tcp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						src_port_range: port_range{
							start:  1024,
							finish: 65535,
						},
						dst_port_range: port_range{
							start:  20,
							finish: 21,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "object NTP host 10.10.10.10 host 10.10.10.1",
			args: args{
				ace_text: "access-list inside_in extended permit object NTP host 10.10.10.10 host 10.10.10.1",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit object NTP host 10.10.10.10 host 10.10.10.1",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    17,
							Title: "udp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						src_port_range: port_range{
							start:  0,
							finish: 122,
						},
						dst_port_range: port_range{
							start:  123,
							finish: 123,
						},
						icmp: icmp_type_code{-1, -1},
					},
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    17,
							Title: "udp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						src_port_range: port_range{
							start:  124,
							finish: 65535,
						},
						dst_port_range: port_range{
							start:  123,
							finish: 123,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "udp host 10.10.10.10 host 10.10.10.1 object-group CHARGEN",
			args: args{
				ace_text: "access-list inside_in extended permit udp host 10.10.10.10 host 10.10.10.1 object-group CHARGEN",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit udp host 10.10.10.10 host 10.10.10.1 object-group CHARGEN",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    17,
							Title: "udp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						dst_port_range: port_range{
							start:  19,
							finish: 19,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "tcp host 10.10.10.10 host 10.10.10.1 object-group MySQL-FTP",
			args: args{
				ace_text: "access-list inside_in extended permit tcp host 10.10.10.10 host 10.10.10.1 object-group MySQL-FTP",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit tcp host 10.10.10.10 host 10.10.10.1 object-group MySQL-FTP",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    6,
							Title: "tcp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						dst_port_range: port_range{
							start:  3306,
							finish: 3306,
						},
						icmp: icmp_type_code{-1, -1},
					},
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    6,
							Title: "tcp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						dst_port_range: port_range{
							start:  20,
							finish: 20,
						},
						icmp: icmp_type_code{-1, -1},
					},
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    6,
							Title: "tcp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a0a0a0a,
							Finish: 0x0a0a0a0a,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						dst_port_range: port_range{
							start:  21,
							finish: 21,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "tcp object-group OMNI-INET host 10.10.10.1",
			args: args{
				ace_text: "access-list inside_in extended permit tcp object-group OMNI-INET host 10.10.10.1",
			},
			want: AccessEntry{
				line: "access-list inside_in extended permit tcp object-group OMNI-INET host 10.10.10.1",
				compiled: []accessEntryCompiled{
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    6,
							Title: "tcp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a640000,
							Finish: 0x0a64ffff,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						icmp: icmp_type_code{-1, -1},
					},
					{
						action: 1,
						proto: &network_entities.Protocol{
							Id:    6,
							Title: "tcp",
						},
						src_addr_range: utils.AddressObject{
							Start:  0x0a650000,
							Finish: 0x0a65ffff,
						},
						dst_addr_range: utils.AddressObject{
							Start:  0x0a0a0a01,
							Finish: 0x0a0a0a01,
						},
						icmp: icmp_type_code{-1, -1},
					},
				},
			},
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.ace_text)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
