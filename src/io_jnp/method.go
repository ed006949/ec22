package io_jnp

import (
	"encoding/xml"
)

func (r *TrueIfExists) UnmarshalXMLAttr(attr xml.Attr) error {
	switch {
	case len(attr.Value) != 0:
		*r = true
	default:
		*r = false
	}
	return nil
}
func (r *TrueIfExists) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	switch *r {
	case true:
		return xml.Attr{
			Name:  name,
			Value: name.Local,
		}, nil
	default:
		return xml.Attr{}, nil
	}
}
