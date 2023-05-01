package sh_ip_route

import (
	"reflect"
	"testing"

	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func Test_parseRoutingEntryStaticAndConnected(t *testing.T) {
	type args struct {
		f_content []string
	}
	tests := []struct {
		name    string
		args    args
		want    []routingEntry
		wantErr bool
	}{
		{
			name: "connected route",
			args: args{
				f_content: []string{
					"C        10.11.12.0 255.255.255.0 is directly connected, inside",
				},
			},
			want: []routingEntry{
				{
					prefix: utils.AddressObject{
						Start:  0x0a0b0c00,
						Finish: 0x0a0b0cff,
					},
					iface: "inside",
				},
			},
			wantErr: false,
		},
		{
			name: "connected and default routes",
			args: args{
				f_content: []string{
					"C        10.11.12.0 255.255.255.0 is directly connected, inside",
					"S*       0.0.0.0 0.0.0.0 [1/0] via 123.123.123.2, outside",
				},
			},
			want: []routingEntry{
				{
					prefix: utils.AddressObject{
						Start:  0x0a0b0c00,
						Finish: 0x0a0b0cff,
					},
					iface: "inside",
				},
				{
					prefix: utils.AddressObject{
						Start:  0x0,
						Finish: 0xffffffff,
					},
					iface: "outside",
				},
			},
			wantErr: false,
		},
		{
			name: "default route",
			args: args{
				f_content: []string{
					"S*       0.0.0.0 0.0.0.0 [1/0] via 123.123.123.2, outside",
				},
			},
			want: []routingEntry{
				{
					prefix: utils.AddressObject{
						Start:  0x0,
						Finish: 0xffffffff,
					},
					iface: "outside",
				},
			},
			wantErr: false,
		},
	}

	ifaces = make(map[string]string)
	ifaces["inside"] = ""
	ifaces["outside"] = ""

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRoutingEntry(tt.args.f_content)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRoutingEntryStaticAndConnected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRoutingEntryStaticAndConnected() = %v, want %v", got, tt.want)
			}
		})
	}
}
