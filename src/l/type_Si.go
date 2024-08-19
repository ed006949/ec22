package l

import (
	"strconv"
)

type SiUint uint

// UnmarshalText simple Si units [kMGTPE] unmarshaller
//
//		10 bits per unit
//
//	 WARNING no overload checks
func (r *SiUint) UnmarshalText(text []byte) error {
	var (
		interim []byte
	)

	for _, b := range text {
		switch b {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			interim = append(interim, b)
			continue
		}
		break
	}

	switch {
	case len(interim) == 0:
		return nil
	}

	*r = SiUint(StripErr1(strconv.ParseUint(string(interim), 10, 0)))

	for _, b := range text[len(interim):] {
		switch b {
		case ' ':
			continue
		case 'k':
			*r <<= 10
		case 'M':
			*r <<= 20
		case 'G':
			*r <<= 30
		case 'T':
			*r <<= 40
		case 'P':
			*r <<= 50
		case 'E':
			*r <<= 60
		}
		break
	}

	return nil
}
