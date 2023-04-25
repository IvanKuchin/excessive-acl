package sh_run_pipe

import (
	"reflect"
	"testing"
)

func Test_SectionExact(t *testing.T) {
	type args struct {
		pattern string
	}
	tests := []struct {
		name string
		args args
		want Text
	}{
		{
			name: "SectionExact",
			args: args{
				pattern: "object service NTP",
			},
			want: Text{
				"object service NTP",
				" service udp source eq ntp destination eq ntp",
			},
		},
	}
	Load("sh_run_test.txt")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SectionExact(tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SectionExact() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Section(t *testing.T) {
	type args struct {
		pattern string
	}
	tests := []struct {
		name string
		args args
		want Text
	}{
		{
			name: "Section",
			args: args{
				pattern: "object service NTP",
			},
			want: Text{
				"object service NTP_source",
				" service udp source eq ntp",
				"object service NTP_destination",
				" service udp destination eq ntp",
				"object service NTP",
				" service udp source eq ntp destination eq ntp",
			},
		},
	}
	// Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Section(tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("section() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestText_Include(t *testing.T) {
	type args struct {
		pattern string
	}
	tests := []struct {
		name string
		tr   Text
		args args
		want Text
	}{
		{
			name: "Obj Text Include",
			tr: Text{
				"object service NTP_source",
				" service udp source eq ntp",
				"object service NTP_destination",
				" service udp destination eq ntp",
				"object service NTP",
				" service udp source eq ntp destination eq ntp",
			},
			args: args{
				pattern: "object service NTP",
			},
			want: Text{
				"object service NTP_source",
				"object service NTP_destination",
				"object service NTP",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tr.Include(tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Text.Include() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExact(t *testing.T) {
	type args struct {
		pattern string
	}
	tests := []struct {
		name string
		args args
		want Text
	}{
		{
			name: "NTP",
			args: args{
				pattern: "object service NTP",
			},
			want: Text{
				"object service NTP",
			},
		},
	}
	Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Exact(tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Exact() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInclude(t *testing.T) {
	type args struct {
		pattern string
	}
	tests := []struct {
		name string
		args args
		want Text
	}{
		{
			name: "NTP",
			args: args{
				pattern: "object service NTP",
			},
			want: Text{
				"object service NTP_source",
				"object service NTP_destination",
				"object service NTP",
			},
		},
	}
	Load("sh_run_test.txt")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Include(tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Include() = %v, want %v", got, tt.want)
			}
		})
	}
}
