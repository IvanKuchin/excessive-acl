package sh_ip_route

import (
	"testing"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/sh-run-pipe"
)

func TestRoutingTable_GetIface(t *testing.T) {
	type args struct {
		ip uint32
	}

	sh_run_pipe.Load("testdata/sh_run_test.txt")
	_rt, _ := Fit("testdata/sh_ip_route_test.txt")

	tests := []struct {
		name    string
		rt      *RoutingTable
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "1.2.3.4 outside",
			rt:   &_rt,
			args: args{
				ip: 0x01020304,
			},
			want:    "outside",
			wantErr: false,
		},
		{
			name: "10.2.3.4 inside",
			rt:   &_rt,
			args: args{
				ip: 0x0a020304,
			},
			want:    "inside",
			wantErr: false,
		},
		{
			name: "10.10.3.4 outside",
			rt:   &_rt,
			args: args{
				ip: 0x0a0a0304,
			},
			want:    "outside",
			wantErr: false,
		},
		{
			name: "10.10.10.4 inside",
			rt:   &_rt,
			args: args{
				ip: 0x0a0a0a04,
			},
			want:    "inside",
			wantErr: false,
		},
		{
			name: "10.10.10.10 outside",
			rt:   &_rt,
			args: args{
				ip: 0x0a0a0a0a,
			},
			want:    "outside",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.rt.GetIface(tt.args.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("RoutingTable.GetIface() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RoutingTable.GetIface() = %v, want %v", got, tt.want)
			}
		})
	}
}
