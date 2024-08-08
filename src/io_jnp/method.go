package io_jnp

import (
	"encoding/xml"
	"regexp"
	"time"

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

func (r *SiIntValue) UnmarshalText(text []byte) error {
	switch value, err := units.FromHumanSize(string(text)); {
	case err != nil:
		return err
	default:
		*r = SiIntValue(value)
		return nil
	}
}

func (r *SiIntValue) MarshalText() ([]byte, error) {
	return []byte(units.HumanSize(float64(*r))), nil
}

func (r *TimeZoneValue) UnmarshalText(text []byte) error {
	var (
		err, err2 error
		value     *time.Location
	)

	switch value, err = time.LoadLocation(string(text)); {
	case err == nil:
		*r = TimeZoneValue(*value)
		return nil
	}

	switch value, err2 = time.LoadLocation("Etc/" + string(text)); {
	case err2 != nil:
		return err // return original error
	default:
		*r = TimeZoneValue(*value)
		return nil
	}
}

func (r *TimeZoneValue) MarshalText() ([]byte, error) {
	var (
		timeLocation = time.Location(*r)
	)
	return regexp.MustCompile("^Etc/").ReplaceAll([]byte(timeLocation.String()), nil), nil
}
