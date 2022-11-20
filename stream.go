package nigori

import (
	"encoding/binary"
	"reflect"
)

type nigoriStream struct {
	Stream []byte
}

func NewNigoriStream(t Type, str string) *nigoriStream {
	ns := &nigoriStream{}
	ns.AppendType(t)
	ns.AppendText(str)
	return ns
}

func size(i interface{}) uint32 {
	return uint32(reflect.TypeOf(i).Size())
}

func (n *nigoriStream) AppendType(t Type) {
	_type := uint32(t)
	b := make([]byte, size(_type)*2)
	binary.BigEndian.PutUint32(b[0:], size(_type))
	binary.BigEndian.PutUint32(b[4:], _type)
	n.Stream = append(n.Stream, b...)
}

func (n *nigoriStream) AppendText(str string) {
	b := make([]byte, size(uint32(0)))
	l := len(str)
	binary.BigEndian.PutUint32(b[0:], uint32(l))
	n.Stream = append(n.Stream, b...)

	n.Stream = append(n.Stream, []byte(str)...)
}
