package l

import (
	"regexp"
	"strconv"
)

type Version uint

var (
	VersionDenominator Version = 1000
)

func (r *Version) UnmarshalText(text []byte) error {
	for _, b := range regexp.MustCompile(`\.`).Split(string(text), -1) {
		switch value, err := strconv.Atoi(b); {
		case err != nil:
			return err
		default:
			*r = *r*VersionDenominator + Version(value)
		}
	}
	return nil
}
func (r *Version) MarshalText() (outbound []byte, err error) {
	var (
		quotient  = *r
		remainder Version
		// to use delim-style op or not to use delim-style op ....
	)
	for {
		quotient, remainder = quotient/VersionDenominator, quotient%VersionDenominator

		switch {
		case quotient == 0 && remainder == 0:
			return
		case len(outbound) == 0:
			outbound = append([]byte(strconv.Itoa(int(remainder))), outbound...)
		case len(outbound) > 0:
			outbound = append([]byte(strconv.Itoa(int(remainder))+"."), outbound...)
		}
	}
}
func (r *Version) Uint(text []byte) error {
	for _, b := range regexp.MustCompile(`\.`).Split(string(text), -1) {
		switch value, err := strconv.Atoi(b); {
		case err != nil:
			return err
		default:
			*r = *r*VersionDenominator + Version(value)
		}
	}
	return nil
}
