package l

import (
	"regexp"
	"strconv"
)

type Version struct {
	Value []uint
	Bytes []byte
}

func (r *Version) UnmarshalText(text []byte) error {
	r.Bytes = text
	for _, b := range regexp.MustCompile(`[^[0-9]]*`).Split(string(r.Bytes), -1) {
		r.Value = append(r.Value, uint(StripErr1(strconv.ParseUint(b, 10, 0))))
	}
	return nil
}
func (r *Version) MarshalText() ([]byte, error) {
	return r.Bytes, nil
}
