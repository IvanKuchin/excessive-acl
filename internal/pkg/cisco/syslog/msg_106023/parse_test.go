package msg106023

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
)

func TestParse(t *testing.T) {
	type args struct {
		fields []string
	}
	tests := []struct {
		name    string
		args    args
		want    network_entities.Flow
		wantErr bool
	}{
		{
			name: "icmp",
			args: args{
				fields: strings.Fields("%ASA-4-106023: Deny icmp src inside:10.10.9.9 dst outside:10.10.10.10 (type 8, code 0) by access-group \"test\" [0x0, 0x0]"),
			},
			want: network_entities.Flow{
				Src_iface: "inside",
				Src_ip:    0x0a0a0909,
				Dst_iface: "outside",
				Dst_ip:    0x0a0a0a0a,
				Protocol:  &network_entities.Protocol{Title: "icmp", Id: 1},
				Icmp_type: 8,
				Icmp_code: 0,
			},
			wantErr: false,
		},
		{
			name: "tcp",
			args: args{
				fields: strings.Fields("%ASA-4-106023: Deny tcp src inside:10.10.9.9/45306 dst outside:150.150.150.150/22 by access-group \"inside_in\" [0x6643b58b, 0x0]"),
			},
			want: network_entities.Flow{
				Src_iface: "inside",
				Src_ip:    0x0a0a0909,
				Src_port:  45306,
				Dst_iface: "outside",
				Dst_ip:    0x96969696,
				Dst_port:  22,
				Protocol:  &network_entities.Protocol{Title: "tcp", Id: 6},
				Icmp_type: -1,
				Icmp_code: -1,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.fields)
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
