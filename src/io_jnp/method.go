package io_jnp

import (
	"encoding/xml"

	"github.com/docker/go-units"
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

func (r *SiValue) UnmarshalText(text []byte) error {
	switch value, err := units.FromHumanSize(string(text)); {
	case err != nil:
		return err
	default:
		*r = SiValue(value)
		return nil
	}
}

func (r *SiValue) MarshalText() ([]byte, error) {
	return []byte(units.HumanSize(float64(*r))), nil
}
