package main

import (
	"encoding/xml"
	"net/netip"

	"ec22/src/l"
)

// ApplyGroup         Names  `xml:"apply_group"`

type NameDesc struct {
	Name        string `xml:"name,attr"`
	Description string `xml:"description,attr"`
}
type ID struct {
	NameDesc
	DomainName string `xml:"domain_name,attr"`
	Contact    string `xml:"contact,attr"`
	AS         uint32 `xml:"as,attr"`
}
type Equipment struct {
	Vendor    string    `xml:"vendor,attr"`
	Model     string    `xml:"model,attr"`
	OSVersion l.Version `xml:"os_version,attr"`
	Mode      string    `xml:"mode,attr"`
	SN        string    `xml:"sn,attr"`
	OOB       string    `xml:"if_unit,attr"`
}
type TILimits struct {
	TIUnitMin uint16 `xml:"ti_unit_min,attr"`
	TIUnitMax uint16 `xml:"ti_unit_max,attr"`
}
type UserList []struct {
	NameDesc
	Password string `xml:"password,attr"`
	UID      uint32 `xml:"uid,attr"`
	Class    string `xml:"class,attr"`
	SSH      []struct {
		AuthorizedKey string `xml:"authorized_key,attr"`
	} `xml:"ssh"`
}
type ServerList struct {
	DNS       Names `xml:"dns"`
	NTP       Names `xml:"ntp"`
	Log       Names `xml:"log"`
	SNMP      Names `xml:"snmp"`
	Archivist Names `xml:"archivist"`
}
type Name struct {
	Name string `xml:"name,attr"`
}
type Names []struct {
	Name string `xml:"name,attr"`
}
type RoutingOptions []struct {
	Import Names `xml:"import"`
	Export Names `xml:"export"`
	Static []struct {
		Destination netip.Prefix `xml:"destination,attr"`
		Action      string       `xml:"action,attr"`
		Target      string       `xml:"target,attr"`
	} `xml:"static"`
}
type RoutingOptionsIE []struct {
	Import Names `xml:"import"`
	Export Names `xml:"export"`
}

type SecurityPolicyElements []struct {
	SourceAddress      Names `xml:"source_address"`
	DestinationAddress Names `xml:"destination_address"`
	Application        Names `xml:"application"`
	Then               Names `xml:"then"`
}
type SecurityPolicy []struct {
	From   Names                  `xml:"from"`
	To     Names                  `xml:"to"`
	Policy SecurityPolicyElements `xml:"policy"`
}
type SecurityPolicyGlobal []struct {
	From   Names                  `xml:"from"`
	To     Names                  `xml:"to"`
	Policy SecurityPolicyElements `xml:"policy"`
}

type Environment struct {
	XMLName xml.Name
	Version l.Version `xml:"version,attr"`
	ID

	FamilyDefault string `xml:"family_default,attr"`

	TITypeDefault string       `xml:"ti_type_default,attr"`
	ST0IPv4       netip.Prefix `xml:"st0_ipv4,attr"`

	TILimits

	DeviceGroup []struct {
		ID

		TILimits

		UserList   `xml:"user_list>user"`
		ServerList `xml:"server_list"`
	} `xml:"device_group_list>device_group"`

	Device []struct {
		ID
		Equipment

		IF []struct {
			NameDesc
			VLANTagging bool `xml:"vlan_tagging,attr"`
			Unit        []struct {
				NameDesc
				VLANID uint16 `xml:"vlan_id,attr"`
				IPv4   []struct {
					IsDHCP      bool         `xml:"dhcp,attr"`
					IsPrimary   bool         `xml:"primary,attr"`
					IsPreferred bool         `xml:"preferred,attr"`
					Address     netip.Prefix `xml:"address,attr"`
				} `xml:"inet>ipv4"`
			} `xml:"unit"`
		} `xml:"if"`

		RI []struct {
			NameDesc
			IFUnit Names          `xml:"if_unit"`
			RO     RoutingOptions `xml:"ro"`
		} `xml:"ri"`

		Zone []struct {
			NameDesc
			Screen string `xml:"screen,attr"`
			IFUnit Names  `xml:"if_unit"`
		} `xml:"zone"`

		// zone-specific security policies (from/to zone any to/from zone any)
		// faster? and more priority
		// from-to combinations will be expanded as "set security policy from-zone A to-zone B policy X" policies
		SecurityPolicy SecurityPolicy `xml:"security_policy"`

		// device-specific security policies (from/to zones any)
		// slower? and less priority
		// from-to combinations will be used in "set security policy global policy X [ from-zone A | to-zone B ]" policies
		SecurityPolicyGlobal SecurityPolicyGlobal `xml:"security_policy_global"`
	} `xml:"device_list>device"`

	TI []struct {
		ID       uint16 `xml:"id,attr"`
		Type     string `xml:"type,attr"`
		TIType   string `xml:"ti_type,attr"`
		AuthType string `xml:"auth_type,attr"`
		AuthName string `xml:"auth_name,attr"`
		Peer     []struct {
			Device      string       `xml:"device,attr"`
			OutsideIF   string       `xml:"outside_if,attr"`
			OutsideIPv4 netip.Prefix `xml:"outside_ipv4,attr"`
			InsideRI    string       `xml:"inside_ri,attr"`
			Type        string       `xml:"type,attr"`
			Import      Names        `xml:"import"`
			Export      Names        `xml:"export"`
		} `xml:"peer"`
	} `xml:"ti_list>ti"`
}
