package main

var (
	SpecialZones = []BuiltInZones{
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
