package ciscoasaaccessgroup

type direction int

const (
	inbound direction = iota
	outbound
)

type Accessgroup struct {
	iface, Acl_name string
	direction       direction
}
