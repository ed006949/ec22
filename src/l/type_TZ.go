package l

import (
	"regexp"
	"time"
)

type TimeZone time.Location

func (r *TimeZone) UnmarshalText(text []byte) error {
	var (
		err        error
		interimErr error
		value      *time.Location
	)

	switch value, err = time.LoadLocation(string(text)); {
	case err == nil:
		*r = TimeZone(*value)
		return nil
	}

	switch value, interimErr = time.LoadLocation("Etc/" + string(text)); {
	case interimErr == nil:
		*r = TimeZone(*value)
		return nil
	}

	return err // return original error
}
func (r *TimeZone) MarshalText() ([]byte, error) {
	var (
		timeLocation = time.Location(*r)
	)
	return regexp.MustCompile("^Etc/").ReplaceAll([]byte(timeLocation.String()), nil), nil
}
