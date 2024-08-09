package l

import (
	"strconv"
)

type SiUint uint

// UnmarshalText simple Si units [kMGTPE] unmarshaller
//
//		10 bits per unit
//
//	 FIXME no overload checks!
func (r *SiUint) UnmarshalText(text []byte) error {
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

	*r = SiUint(StripErr1(strconv.ParseUint(string(interim), 10, 0)))
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

// func (r *SiUint) MarshalText() ([]byte, error) {
// 	return []byte(strconv.Itoa(int(*r))), nil
// }
