package sh_ip_route

import (
	"reflect"
	"testing"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/sh-run-pipe"
)

func Test_findAllIfaceNames(t *testing.T) {
	tests := []struct {
		name    string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "inside and outside",
			want: map[string]string{
				"inside":  "",
				"outside": "",
			},
			wantErr: false,
		},
	}
	sh_run_pipe.Load("testdata/sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findAllIfaceNames()
			if (err != nil) != tt.wantErr {
				t.Errorf("findAllIfaceNames() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findAllIfaceNames() = %v, want %v", got, tt.want)
			}
		})
	}
}
