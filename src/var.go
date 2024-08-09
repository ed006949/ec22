package main

var (
	SpecialZones = []struct {
		RIName      string
		ZoneName    string
		Description string
		IF          []string
	}{
		{
			RIName:      "",
			ZoneName:    "functional-zone",
			Description: "",
			IF:          nil,
		},
		{
			RIName:      "",
			ZoneName:    "junos-host",
			Description: "",
			IF:          nil,
		},
		{
			RIName:      "mgmt_junos",
			ZoneName:    "",
			Description: "MANAGEMENT-INSTANCE",
			IF:          []string{"fxp0"},
		},
		{
			RIName:      "",
			ZoneName:    "master",
			Description: "",
			IF:          nil,
		},
	}
)
