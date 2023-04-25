package ciscoasaaccessentry

import (
	"reflect"
	"testing"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list/sh-run-pipe"
	"github.com/ivankuchin/excessive-acl/internal/network_entities"
)

func Test_isServiceAtAPosition(t *testing.T) {
	type args struct {
		parsing_pos uint
		fields      []string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "eq",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "eq", "20", "log"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "lt",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "lt", "20", "log"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "gt",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "gt", "20", "log"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "neq",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "neq", "20", "log"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "range 20 21",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "range", "20", "21", "log"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "range 20",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "range", "20"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "object-group FTP",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "object-group", "FTP"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "object-group FTP fail",
			args: args{
				parsing_pos: 9,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "OMNI-INET", "any4", "object-group"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "icmp type",
			args: args{
				parsing_pos: 8,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "icmp", "object-group", "OMNI-INET", "any4", "time-exceeded"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "icmp type code",
			args: args{
				parsing_pos: 8,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "icmp", "object-group", "OMNI-INET", "any4", "time-exceeded", "128"},
			},
			want:    true,
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isServiceAtAPosition(tt.args.parsing_pos, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("isServiceAtAPosition() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isServiceAtAPosition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isServiceAtAPositionTCPUDP(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "tcp",
			args: args{
				name: "FTP",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "udp",
			args: args{
				name: "CHARGEN",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "tcp-udp",
			args: args{
				name: "SIP",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "unknown",
			args: args{
				name: "unknown",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "partially overlapped name",
			args: args{
				name: "DLINK",
			},
			want:    false,
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isServiceAtAPositionTCPUDP(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("isServiceAtAPositionTCPUDP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isServiceAtAPositionTCPUDP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isIcmpTypeCodeAtAPosition(t *testing.T) {
	type args struct {
		parsing_pos uint
		fields      []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ok time-exceeded",
			args: args{
				parsing_pos: 8,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "icmp", "object-group", "OMNI-INET", "any4", "time-exceeded", "128"},
			},
			want: true,
		},
		{
			name: "ok 128",
			args: args{
				parsing_pos: 8,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "icmp", "object-group", "OMNI-INET", "any4", "128", "128"},
			},
			want: true,
		},
		{
			name: "not ok 1",
			args: args{
				parsing_pos: 8,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "icmp", "object-group", "OMNI-INET", "any4", "unknown", "128"},
			},
			want: false,
		},
		{
			name: "not ok 2",
			args: args{
				parsing_pos: 8,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "icmp", "object-group", "OMNI-INET", "any4"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIcmpTypeCodeAtAPosition(tt.args.parsing_pos, tt.args.fields); got != tt.want {
				t.Errorf("isIcmpTypeCodeAtAPosition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parsePortRange(t *testing.T) {
	type args struct {
		parsing_pos uint
		fields      []string
		proto       *network_entities.Protocol
	}
	tests := []struct {
		name    string
		args    args
		want    uint
		want1   []port_range
		wantErr bool
	}{
		{
			name: "tcp udp named port",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "tcp", "source", "eq", "https", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 6, Title: "tcp"}},
			want:    5,
			want1:   []port_range{{start: 443, finish: 443}},
			wantErr: false,
		},
		{
			name: "tcp udp numbered port",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "tcp", "source", "eq", "443", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 6, Title: "tcp"}},
			want:    5,
			want1:   []port_range{{start: 443, finish: 443}},
			wantErr: false,
		},
		{
			name: "tcp udp source part only",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "tcp", "source", "eq", "443"},
				proto:       &network_entities.Protocol{Id: 6, Title: "tcp"}},
			want:    5,
			want1:   []port_range{{start: 443, finish: 443}},
			wantErr: false,
		},
		{
			name: "tcp udp destination eq part parsing",
			args: args{
				parsing_pos: 6,
				fields:      []string{"service", "tcp", "source", "eq", "443", "destination", "eq", "https"},
				proto:       &network_entities.Protocol{Id: 6, Title: "tcp"}},
			want:    8,
			want1:   []port_range{{start: 443, finish: 443}},
			wantErr: false,
		},
		{
			name: "tcp udp destination range part parsing",
			args: args{
				parsing_pos: 6,
				fields:      []string{"service", "tcp", "source", "eq", "443", "destination", "range", "www", "https"},
				proto:       &network_entities.Protocol{Id: 6, Title: "tcp"}},
			want:    9,
			want1:   []port_range{{start: 80, finish: 443}},
			wantErr: false,
		},
		{
			name: "tcp udp lt operator",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "udp", "source", "lt", "ntp", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 17, Title: "udp"}},
			want:    5,
			want1:   []port_range{{start: 0, finish: 122}},
			wantErr: false,
		},
		{
			name: "tcp udp gt operator",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "udp", "source", "gt", "ntp", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 17, Title: "udp"}},
			want:    5,
			want1:   []port_range{{start: 124, finish: 65535}},
			wantErr: false,
		},
		{
			name: "tcp udp eq operator",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "udp", "source", "eq", "ntp", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 17, Title: "udp"}},
			want:    5,
			want1:   []port_range{{start: 123, finish: 123}},
			wantErr: false,
		},
		{
			name: "tcp udp neq operator",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "udp", "source", "neq", "ntp", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 17, Title: "udp"}},
			want:    5,
			want1:   []port_range{{start: 0, finish: 122}, {start: 124, finish: 65535}},
			wantErr: false,
		},
		{
			name: "tcp udp range operator",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "udp", "source", "range", "http", "https", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 17, Title: "udp"}},
			want:    6,
			want1:   []port_range{{start: 80, finish: 443}},
			wantErr: false,
		},
		{
			name: "tcp udp unknown port name",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "tcp", "source", "range", "unknown", "https", "destination", "eq", "123"},
				proto:       &network_entities.Protocol{Id: 6, Title: "tcp"}},
			want:    0,
			want1:   nil,
			wantErr: true,
		},
		{
			name: "tcp udp incomplete service object",
			args: args{
				parsing_pos: 3,
				fields:      []string{"service", "tcp", "source", "range", "www"},
				proto:       &network_entities.Protocol{Id: 6, Title: "tcp"}},
			want:    0,
			want1:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := parsePortRange(tt.args.parsing_pos, tt.args.fields, tt.args.proto)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePortRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parsePortRange() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("parsePortRange() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_parsePortGroup(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    []port_range
		wantErr bool
	}{
		{
			name: "range",
			args: args{
				name: "SIP",
			},
			want: []port_range{
				{
					start:  5060,
					finish: 5061,
				},
			},
			wantErr: false,
		},
		{
			name: "eq",
			args: args{
				name: "FTP",
			},
			want: []port_range{
				{
					start:  20,
					finish: 20,
				},
				{
					start:  21,
					finish: 21,
				},
			},
			wantErr: false,
		},
		{
			name: "nested group-object",
			args: args{
				name: "MySQL-FTP",
			},
			want: []port_range{
				{
					start:  3306,
					finish: 3306,
				},
				{
					start:  20,
					finish: 20,
				},
				{
					start:  21,
					finish: 21,
				},
			},
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePortGroup(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePortGroup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePortGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseIcmpTypeCode(t *testing.T) {
	type args struct {
		parsing_pos uint
		fields      []string
	}
	tests := []struct {
		name    string
		args    args
		want    uint
		want1   []icmp_type_code
		wantErr bool
	}{
		{
			name: "icmp named port",
			args: args{
				parsing_pos: 2,
				fields:      []string{"service", "icmp", "echo"},
			},
			want:    3,
			want1:   []icmp_type_code{{icmp_type: 8, icmp_code: -1}},
			wantErr: false,
		},
		{
			name: "icmp numbered port",
			args: args{
				parsing_pos: 2,
				fields:      []string{"service", "icmp", "11"},
			},
			want:    3,
			want1:   []icmp_type_code{{icmp_type: 11, icmp_code: -1}},
			wantErr: false,
		},
		{
			name: "icmp type and code",
			args: args{
				parsing_pos: 2,
				fields:      []string{"service", "icmp", "11", "0"},
			},
			want:    4,
			want1:   []icmp_type_code{{icmp_type: 11, icmp_code: 0}},
			wantErr: false,
		},
		{
			name: "icmp no type and no code",
			args: args{
				parsing_pos: 2,
				fields:      []string{"service", "icmp"},
			},
			want:    2,
			want1:   []icmp_type_code{{icmp_type: -1, icmp_code: -1}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := parseIcmpTypeCode(tt.args.parsing_pos, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIcmpTypeCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseIcmpTypeCode() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("parseIcmpTypeCode() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_parseServiceObjectContent(t *testing.T) {
	type args struct {
		fields []string
	}
	tests := []struct {
		name    string
		args    args
		want    *serviceObject
		wantErr bool
	}{
		{
			name: "tcp udp named and numbered port",
			args: args{
				fields: []string{"tcp", "source", "range", "1024", "65535", "destination", "eq", "443"},
			},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 6, Title: "tcp"}},
				src_port_range: []port_range{{start: 1024, finish: 65535}},
				dst_port_range: []port_range{{start: 443, finish: 443}},
				icmp:           nil,
			},
			wantErr: false,
		},
		{
			name: "tcp udp source only",
			args: args{
				fields: []string{"tcp", "source", "range", "1024", "65535"},
			},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 6, Title: "tcp"}},
				src_port_range: []port_range{{start: 1024, finish: 65535}},
				dst_port_range: nil,
				icmp:           nil,
			},
			wantErr: false,
		},
		{
			name: "tcp udp destination only",
			args: args{
				fields: []string{"tcp", "destination", "eq", "443"},
			},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 6, Title: "tcp"}},
				src_port_range: nil,
				dst_port_range: []port_range{{start: 443, finish: 443}},
				icmp:           nil,
			},
			wantErr: false,
		},
		{
			name: "tcp udp protocol only",
			args: args{
				fields: []string{"tcp"},
			},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 6, Title: "tcp"}},
				src_port_range: nil,
				dst_port_range: nil,
				icmp:           nil,
			},
			wantErr: false,
		},
		{
			name: "icmp protocol only",
			args: args{
				fields: []string{"icmp"},
			},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 1, Title: "icmp"}},
				src_port_range: nil,
				dst_port_range: nil,
				icmp:           nil,
			},
			wantErr: false,
		},
		{
			name: "icmp and type",
			args: args{
				fields: []string{"icmp", "echo"},
			},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 1, Title: "icmp"}},
				src_port_range: nil,
				dst_port_range: nil,
				icmp:           []icmp_type_code{{icmp_type: 8, icmp_code: -1}},
			},
			wantErr: false,
		},
		{
			name: "icmp and type and code",
			args: args{
				fields: []string{"icmp", "echo", "11"},
			},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 1, Title: "icmp"}},
				src_port_range: nil,
				dst_port_range: nil,
				icmp:           []icmp_type_code{{icmp_type: 8, icmp_code: 11}},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseServiceObjectContent(tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseServiceObjectContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseServiceObjectContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseServiceObject(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    *serviceObject
		wantErr bool
	}{
		{
			name: "service object parsing tcp udp",
			args: args{name: "NTP"},
			want: &serviceObject{
				proto: []*network_entities.Protocol{{Id: 17, Title: "udp"}},
				src_port_range: []port_range{
					{start: 0, finish: 122},
					{start: 124, finish: 65535},
				},
				dst_port_range: []port_range{
					{start: 123, finish: 123},
				},
				icmp: nil,
			},
			wantErr: false,
		},
		{
			name: "service object parsing tcp udp source only",
			args: args{name: "NTP_source"},
			want: &serviceObject{
				proto: []*network_entities.Protocol{{Id: 17, Title: "udp"}},
				src_port_range: []port_range{
					{start: 123, finish: 123},
				},
				dst_port_range: nil,
				icmp:           nil,
			},
			wantErr: false,
		},
		{
			name: "service object parsing tcp udp destination only",
			args: args{name: "NTP_destination"},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 17, Title: "udp"}},
				src_port_range: nil,
				dst_port_range: []port_range{
					{start: 123, finish: 123},
				},
				icmp: nil,
			},
			wantErr: false,
		},
		{
			name: "service object parsing icmp",
			args: args{name: "ICMP"},
			want: &serviceObject{
				proto:          []*network_entities.Protocol{{Id: 1, Title: "icmp"}},
				src_port_range: nil,
				dst_port_range: nil,
				icmp:           []icmp_type_code{{icmp_type: 8, icmp_code: 0}},
			},
			wantErr: false,
		},
		{
			name:    "unknown service object",
			args:    args{name: "unknown"},
			want:    nil,
			wantErr: true,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseServiceObject(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseServiceObject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseServiceObject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseServiceObjectGroup(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    []serviceObject
		wantErr bool
	}{
		{
			name: "OMNI-PORTS",
			args: args{name: "OMNI-PORTS"},
			want: []serviceObject{
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					src_port_range: nil,
					dst_port_range: []port_range{
						{start: 1, finish: 20},
					},
					icmp: nil,
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					src_port_range: nil,
					dst_port_range: []port_range{
						{start: 22, finish: 65535},
					},
					icmp: nil,
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 1, Title: "icmp"},
					},
					src_port_range: nil,
					dst_port_range: nil,
					icmp: []icmp_type_code{
						{icmp_type: 8, icmp_code: -1},
					},
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 1, Title: "icmp"},
					},
					src_port_range: nil,
					dst_port_range: nil,
					icmp: []icmp_type_code{
						{icmp_type: 0, icmp_code: -1},
					},
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					src_port_range: []port_range{
						{start: 0, finish: 20},
						{start: 22, finish: 65535},
					},
					dst_port_range: nil,
					icmp:           nil,
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					src_port_range: []port_range{
						{start: 0, finish: 20},
						{start: 22, finish: 65535},
					},
					dst_port_range: []port_range{
						{start: 1025, finish: 65535},
					},
					icmp: nil,
				},
			},
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseServiceObjectGroup(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseServiceObjectGroup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseServiceObjectGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getProtocolOrServiceObject(t *testing.T) {
	type args struct {
		parsing_pos uint
		fields      []string
	}
	tests := []struct {
		name    string
		args    args
		want    uint
		want1   []serviceObject
		wantErr bool
	}{
		{
			name: "tcp",
			args: args{parsing_pos: 4, fields: []string{"access-list", "xxx", "extended", "permit", "tcp", "object-group", "xxx", "object-group", "xxx"}},
			want: 5,
			want1: []serviceObject{
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "object",
			args: args{parsing_pos: 4, fields: []string{"access-list", "xxx", "extended", "permit", "object", "NTP_destination", "object-group", "xxx", "object-group", "xxx"}},
			want: 6,
			want1: []serviceObject{
				{
					proto: []*network_entities.Protocol{
						{Id: 17, Title: "udp"},
					},
					dst_port_range: []port_range{
						{start: 123, finish: 123},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "object-group service",
			args: args{parsing_pos: 4, fields: []string{"access-list", "xxx", "extended", "permit", "object-group", "OMNI-PORTS", "object-group", "xxx", "object-group", "xxx"}},
			want: 6,
			want1: []serviceObject{
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					dst_port_range: []port_range{
						{start: 1, finish: 20},
					},
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					dst_port_range: []port_range{
						{start: 22, finish: 65535},
					},
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 1, Title: "icmp"},
					},
					icmp: []icmp_type_code{
						{icmp_type: 8, icmp_code: -1},
					},
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 1, Title: "icmp"},
					},
					icmp: []icmp_type_code{
						{icmp_type: 0, icmp_code: -1},
					},
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					src_port_range: []port_range{
						{start: 0, finish: 20},
						{start: 22, finish: 65535},
					},
				},
				{
					proto: []*network_entities.Protocol{
						{Id: 6, Title: "tcp"},
						{Id: 17, Title: "udp"},
					},
					src_port_range: []port_range{
						{start: 0, finish: 20},
						{start: 22, finish: 65535},
					},
					dst_port_range: []port_range{
						{start: 1025, finish: 65535},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "object-group protocol",
			args: args{parsing_pos: 4, fields: []string{"access-list", "xxx", "extended", "permit", "object-group", "TCPUDP", "object-group", "xxx", "object-group", "xxx"}},
			want: 6,
			want1: []serviceObject{
				{
					proto: []*network_entities.Protocol{
						{Id: 17, Title: "udp"},
						{Id: 6, Title: "tcp"},
					},
				},
			},
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getProtocolOrServiceObject(tt.args.parsing_pos, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("getProtocolOrServiceObject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getProtocolOrServiceObject() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getProtocolOrServiceObject() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
