package msg302013

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
			name: "inbound",
			args: args{
				fields: strings.Fields("%ASA-6-302013: Built inbound TCP connection 54 for outside:150.150.150.150/57346 (150.150.150.150/57346) to dmz:172.16.16.16/22 (123.123.123.10/22)"),
			},
			want: network_entities.Flow{
				Src_iface: "outside",
				Src_ip:    0x96969696,
				Src_port:  57346,
				Dst_iface: "dmz",
				Dst_ip:    0xac101010,
				Dst_port:  22,
				Protocol:  &network_entities.Protocol{Title: "tcp", Id: 6},
				Icmp_type: -1,
				Icmp_code: -1,
			},
			wantErr: false,
		},
		{
			name: "outbound",
			args: args{
				fields: strings.Fields("%ASA-6-302015: Built outbound UDP connection 54 for outside:150.150.150.150/22 (150.150.150.150/2) to dmz:172.16.16.16/57346 (123.123.123.10/7346)"),
			},
			want: network_entities.Flow{
				Src_iface: "dmz",
				Src_ip:    0xac101010,
				Src_port:  57346,
				Dst_iface: "outside",
				Dst_ip:    0x96969696,
				Dst_port:  22,
				Protocol:  &network_entities.Protocol{Title: "udp", Id: 17},
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
