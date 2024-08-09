package io_jnp

import (
	"encoding/xml"
	"regexp"
	"strconv"
	"time"

	"ec22/src/l"
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
	var (
		interim []byte
		element byte
	)

	for _, element = range text {
		switch {
		case '0' <= element && element <= '9':
			interim = append(interim, element)
			continue
		}
		break
	}

	*r = SiValue(l.StripErr1(strconv.ParseUint(string(interim), 10, 0)))
	switch string(element) { // kMGTPE
	case "k":
		*r = *r << 10
	case "M":
		*r = *r << 20
	case "G":
		*r = *r << 30
	case "T":
		*r = *r << 40
	case "P":
		*r = *r << 50
	case "E":
		*r = *r << 60
	}

	return nil
}

// func (r *SiValue) MarshalText() ([]byte, error) {
// 	return []byte(strconv.Itoa(int(*r))), nil
// }

func (r *TimeZoneValue) UnmarshalText(text []byte) error {
	var (
		err        error
		interimErr error
		value      *time.Location
	)

	switch value, err = time.LoadLocation(string(text)); {
	case err == nil:
		*r = TimeZoneValue(*value)
		return nil
	}

	switch value, interimErr = time.LoadLocation("Etc/" + string(text)); {
	case interimErr == nil:
		*r = TimeZoneValue(*value)
		return nil
	}

	return err // return original error
}
func (r *TimeZoneValue) MarshalText() ([]byte, error) {
	var (
		timeLocation = time.Location(*r)
	)
	return regexp.MustCompile("^Etc/").ReplaceAll([]byte(timeLocation.String()), nil), nil
}
