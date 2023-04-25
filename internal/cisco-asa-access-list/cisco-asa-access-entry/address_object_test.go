package ciscoasaaccessentry

import (
	"reflect"
	"testing"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list/sh-run-pipe"
)

func Test_parseMask(t *testing.T) {
	type args struct {
		mask_str string
	}
	tests := []struct {
		name    string
		args    args
		want    uint32
		wantErr bool
	}{
		{
			name: "parseMask 0",
			args: args{
				mask_str: "0.0.0.0",
			},
			want:    0,
			wantErr: false,
		},
		{
			name: "parseMask 128",
			args: args{
				mask_str: "128.0.0.0",
			},
			want:    128<<24 + 0<<16 + 0<<8 + 0,
			wantErr: false,
		},
		{
			name: "parseMask 224",
			args: args{
				mask_str: "224.0.0.0",
			},
			want:    224<<24 + 0<<16 + 0<<8 + 0,
			wantErr: false,
		},
		{
			name: "parseMask 255",
			args: args{
				mask_str: "255.0.0.0",
			},
			want:    255<<24 + 0<<16 + 0<<8 + 0,
			wantErr: false,
		},
		{
			name: "parseMask 255.255",
			args: args{
				mask_str: "255.255.0.0",
			},
			want:    255<<24 + 255<<16 + 0<<8 + 0,
			wantErr: false,
		},
		{
			name: "parseMask 255.255.255",
			args: args{
				mask_str: "255.255.255.0",
			},
			want:    255<<24 + 255<<16 + 255<<8 + 0,
			wantErr: false,
		},
		{
			name: "parseMask 255.255.255.255",
			args: args{
				mask_str: "255.255.255.255",
			},
			want:    255<<24 + 255<<16 + 255<<8 + 255,
			wantErr: false,
		},
		{
			name: "parseMask 255.254.255.255",
			args: args{
				mask_str: "255.254.255.255",
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMask(tt.args.mask_str)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMask() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseMask() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseIP(t *testing.T) {
	type args struct {
		ip_str string
	}
	tests := []struct {
		name    string
		args    args
		want    uint32
		wantErr bool
	}{
		{
			name: "0.0.0.0",
			args: args{
				ip_str: "0.0.0.0",
			},
			want:    0,
			wantErr: false,
		},
		{
			name: "10.0.0.0",
			args: args{
				ip_str: "10.0.0.0",
			},
			want:    10<<24 + 0<<16 + 0<<8 + 0,
			wantErr: false,
		},

		{
			name: "172.16.0.0",
			args: args{
				ip_str: "172.16.0.0",
			},
			want:    172<<24 + 16<<16 + 0<<8 + 0,
			wantErr: false,
		},
		{
			name: "192.168.0.0",
			args: args{
				ip_str: "192.168.0.0",
			},
			want:    192<<24 + 168<<16 + 0<<8 + 0,
			wantErr: false,
		},
		{
			name: "11.12.13.14.15",
			args: args{
				ip_str: "11.12.13.14.15",
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIP(tt.args.ip_str)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseSubnet(t *testing.T) {
	type args struct {
		parsing_pos uint
		fields      []string
	}
	tests := []struct {
		name    string
		args    args
		want    uint
		want1   addressObject
		wantErr bool
	}{
		{
			name: "0.0.0.0 0.0.0.0",
			args: args{
				parsing_pos: 0,
				fields:      []string{"0.0.0.0", "0.0.0.0"},
			},
			want:    2,
			want1:   addressObject{0, 4294967295},
			wantErr: false,
		},
		{
			name: "10.0.0.0 255.0.0.0",
			args: args{
				parsing_pos: 0,
				fields:      []string{"10.0.0.0", "255.0.0.0"},
			},
			want: 2,
			want1: addressObject{
				uint32(10)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0),
				uint32(10)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0)),
			},
			wantErr: false,
		},
		{
			name: "172.16.0.0 255.240.0.0",
			args: args{
				parsing_pos: 0,
				fields:      []string{"172.16.0.0", "255.240.0.0"},
			},
			want: 2,
			want1: addressObject{
				uint32(172)<<24 + uint32(16)<<16 + uint32(0)<<8 + uint32(0),
				uint32(172)<<24 + uint32(16)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(240)<<16 + uint32(0)<<8 + uint32(0)),
			},
			wantErr: false,
		},
		{
			name: "192.168.0.0 255.255.0.0",
			args: args{
				parsing_pos: 0,
				fields:      []string{"192.168.0.0", "255.255.0.0"},
			},
			want: 2,
			want1: addressObject{
				uint32(192)<<24 + uint32(168)<<16 + uint32(0)<<8 + uint32(0),
				uint32(192)<<24 + uint32(168)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(0)<<8 + uint32(0)),
			},
			wantErr: false,
		},
		{
			name: "192.168.0.0.0 255.255.0.0",
			args: args{
				parsing_pos: 0,
				fields:      []string{"192.168.0.0.0", "255.255.0.0"},
			},
			want:    0,
			want1:   addressObject{},
			wantErr: true,
		},
		{
			name: "192.168.0.0.0255.255.0.0",
			args: args{
				parsing_pos: 0,
				fields:      []string{"192.168.0.0.0255.255.0.0"},
			},
			want:    0,
			want1:   addressObject{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := parseSubnet(tt.args.parsing_pos, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSubnet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseSubnet() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("parseSubnet() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_parseAddressObjectContent(t *testing.T) {
	type args struct {
		fields []string
	}
	tests := []struct {
		name    string
		args    args
		want    addressObject
		wantErr bool
	}{
		{
			name: "host",
			args: args{
				fields: []string{"host", "1.2.3.4"},
			},
			want: addressObject{
				uint32(1)<<24 + uint32(2)<<16 + uint32(3)<<8 + uint32(4),
				uint32(1)<<24 + uint32(2)<<16 + uint32(3)<<8 + uint32(4),
			},
			wantErr: false,
		},
		{
			name: "subnet",
			args: args{
				fields: []string{"subnet", "10.11.12.0", "255.255.255.0"},
			},
			want: addressObject{
				uint32(10)<<24 + uint32(11)<<16 + uint32(12)<<8 + uint32(0),
				uint32(10)<<24 + uint32(11)<<16 + uint32(12)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(0)),
			},
			wantErr: false,
		},
		{
			name: "range",
			args: args{
				fields: []string{"range", "172.16.17.18", "172.16.17.99"},
			},
			want: addressObject{
				uint32(172)<<24 + uint32(16)<<16 + uint32(17)<<8 + uint32(18),
				uint32(172)<<24 + uint32(16)<<16 + uint32(17)<<8 + uint32(99),
			},
			wantErr: false,
		},
		{
			name: "unknown",
			args: args{
				fields: []string{"unknown"},
			},
			want:    addressObject{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAddressObjectContent(tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAddressObjectContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAddressObjectContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseAddressObject(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    addressObject
		wantErr bool
	}{
		{
			name: "host",
			args: args{
				name: "SMALL-DC-RI",
			},
			want: addressObject{
				uint32(192)<<24 + uint32(168)<<16 + uint32(50)<<8 + uint32(50),
				uint32(192)<<24 + uint32(168)<<16 + uint32(50)<<8 + uint32(50),
			},
			wantErr: false,
		},
		{
			name: "subnet",
			args: args{
				name: "SMALL-DC-NH",
			},
			want: addressObject{
				uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0),
				uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(0)),
			},
			wantErr: false,
		},
		{
			name: "range",
			args: args{
				name: "SMALL-DC-MA",
			},
			want: addressObject{
				uint32(192)<<24 + uint32(168)<<16 + uint32(100)<<8 + uint32(50),
				uint32(192)<<24 + uint32(168)<<16 + uint32(100)<<8 + uint32(89),
			},
			wantErr: false,
		},
		{
			name: "unknown",
			args: args{
				name: "unknown",
			},
			want:    addressObject{},
			wantErr: true,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAddressObject(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAddressObject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAddressObject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getAddressObjects(t *testing.T) {
	type args struct {
		parsing_pos uint
		fields      []string
	}
	tests := []struct {
		name    string
		args    args
		want    uint
		want1   []addressObject
		wantErr bool
	}{
		{
			name: "object network host",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "object", "SMALL-DC-RI"},
			},
			want: 7,
			want1: []addressObject{
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(50)<<8 + uint32(50),
					uint32(192)<<24 + uint32(168)<<16 + uint32(50)<<8 + uint32(50),
				},
			},
			wantErr: false,
		},
		{
			name: "object network subnet",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "object", "SMALL-DC-NH"},
			},
			want: 7,
			want1: []addressObject{
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0),
					uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(0)),
				},
			},
			wantErr: false,
		},
		{
			name: "object network range",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "object", "SMALL-DC-MA"},
			},
			want: 7,
			want1: []addressObject{
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(100)<<8 + uint32(50),
					uint32(192)<<24 + uint32(168)<<16 + uint32(100)<<8 + uint32(89),
				},
			},
			wantErr: false,
		},
		{
			name: "object network unknown",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "object", "unknown"},
			},
			want:    0,
			want1:   nil,
			wantErr: true,
		},
		{
			name: "any4",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "any4"},
			},
			want:    6,
			want1:   []addressObject{{0, 0xffffffff}},
			wantErr: false,
		},
		{
			name: "any",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "any"},
			},
			want:    6,
			want1:   []addressObject{{0, 0xffffffff}},
			wantErr: false,
		},
		{
			name: "host",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "host", "192.168.169.170"},
			},
			want: 7,
			want1: []addressObject{
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(169)<<8 + uint32(170),
					uint32(192)<<24 + uint32(168)<<16 + uint32(169)<<8 + uint32(170),
				},
			},
			wantErr: false,
		},
		{
			name: "subnet",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "192.168.170.0", "255.255.255.0"},
			},
			want: 7,
			want1: []addressObject{
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0),
					uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(0)),
				},
			},
			wantErr: false,
		},
		{
			name: "object group network",
			args: args{
				parsing_pos: 5,
				fields:      []string{"access-list", "inside_in", "extended", "permit", "ip", "object-group", "US-NE"},
			},
			want: 7,
			want1: []addressObject{
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0),
					uint32(192)<<24 + uint32(168)<<16 + uint32(170)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(0)),
				},
				{
					uint32(10)<<24 + uint32(11)<<16 + uint32(12)<<8 + uint32(13),
					uint32(10)<<24 + uint32(11)<<16 + uint32(12)<<8 + uint32(13),
				},
				{
					uint32(100)<<24 + uint32(64)<<16 + uint32(0)<<8 + uint32(0),
					uint32(100)<<24 + uint32(64)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(192)<<16 + uint32(0)<<8 + uint32(0)),
				},
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(0)<<8 + uint32(0),
					uint32(192)<<24 + uint32(168)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(0)<<8 + uint32(0)),
				},
				{
					uint32(172)<<24 + uint32(16)<<16 + uint32(0)<<8 + uint32(0),
					uint32(172)<<24 + uint32(16)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(240)<<16 + uint32(0)<<8 + uint32(0)),
				},
				{
					uint32(10)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0),
					uint32(10)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0)),
				},
			},
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getAddressObjects(tt.args.parsing_pos, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAddressObjects() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getAddressObjects() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getAddressObjects() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_parseAddressObjectGroup(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    []addressObject
		wantErr bool
	}{
		{
			name: "rfc1918",
			args: args{
				name: "RFC1918",
			},
			want: []addressObject{
				{
					uint32(192)<<24 + uint32(168)<<16 + uint32(0)<<8 + uint32(0),
					uint32(192)<<24 + uint32(168)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(255)<<16 + uint32(0)<<8 + uint32(0)),
				},
				{
					uint32(172)<<24 + uint32(16)<<16 + uint32(0)<<8 + uint32(0),
					uint32(172)<<24 + uint32(16)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(240)<<16 + uint32(0)<<8 + uint32(0)),
				},
				{
					uint32(10)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0),
					uint32(10)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0) | ^(uint32(255)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0)),
				},
			},
			wantErr: false,
		},
		{
			name: "overlapped name",
			args: args{
				name: "DLINK",
			},
			want: []addressObject{
				{
					uint32(10)<<24 + uint32(12)<<16 + uint32(14)<<8 + uint32(16),
					uint32(10)<<24 + uint32(12)<<16 + uint32(14)<<8 + uint32(16),
				},
			},
			wantErr: false,
		},
	}
	sh_run_pipe.Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAddressObjectGroup(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAddressObjectGroup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAddressObjectGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}
