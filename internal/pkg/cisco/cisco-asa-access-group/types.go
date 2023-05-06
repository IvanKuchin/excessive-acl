package ciscoasaaccessgroup

type direction int

const (
	Inbound direction = iota
	Outbound
)

type Accessgroup struct {
	Iface, Acl_name string
	Direction       direction
}
