package io_jnp

import (
	"time"
)

type TrueIfExists bool
type SiIntValue int
type TimeZoneValue time.Location

// type MinVersionValue string

type ConfigElementFlags struct {
	Unsupported TrueIfExists `xml:"unsupported,attr,omitempty"`
	Inactive    TrueIfExists `xml:"inactive,attr,omitempty"`
	MinVersion  string       `xml:"-"`
	// MinVersion  MinVersionValue `xml:"-"`
}

type IsExists *struct {
	ConfigElementFlags
}
type SiInt *struct {
	ConfigElementFlags
	Value SiIntValue `xml:",chardata"`
}
type Int *struct {
	ConfigElementFlags
	Value int `xml:",chardata"`
}
type String *struct {
	ConfigElementFlags
	Value string `xml:",chardata"`
}

type EncryptedPassword *struct {
	ConfigElementFlags
	Value string `xml:",chardata"`
}
type Password *struct {
	ConfigElementFlags
	Value string `xml:",chardata"`
}
type TimeZone *struct {
	ConfigElementFlags
	Value TimeZoneValue `xml:",chardata"`
}
type SSHPubKey *struct {
	ConfigElementFlags
	Value string `xml:",chardata"`
}

type IsDisable *struct {
	ConfigElementFlags
	Disable IsExists `xml:"disable,omitempty"`
}
type FlowMSS *struct {
	ConfigElementFlags
	MSS Int `xml:"mss,omitempty"`
}
type PolicyStatementTerm []struct {
	ConfigElementFlags
	Name String `xml:"name,omitempty"`
	From *struct {
		ConfigElementFlags
		Protocol         []String `xml:"protocol,omitempty"`
		RouteType        []String `xml:"route-type,omitempty"`
		Instance         []String `xml:"instance,omitempty"`
		PrefixListFilter []struct {
			ConfigElementFlags
			ListName String   `xml:"list_name,omitempty"`
			Exact    IsExists `xml:"exact,omitempty"`
			Longer   IsExists `xml:"longer,omitempty"`
			Orkonger IsExists `xml:"orlonger,omitempty"`
		} `xml:"prefix-list-filter,omitempty"`
	} `xml:"from,omitempty"`
	Then *struct {
		ConfigElementFlags
		LoadBalance *struct {
			ConfigElementFlags
			PerPacket IsExists `xml:"per-packet,omitempty"`
		} `xml:"load-balance,omitempty"`
		Metric *struct {
			ConfigElementFlags
			Add    Int `xml:"add,omitempty"`
			Metric Int `xml:"metric,omitempty"`
		} `xml:"metric,omitempty"`
		NextHop *struct {
			ConfigElementFlags
			Self IsExists `xml:"self,omitempty"`
		} `xml:"next-hop,omitempty"`
		Accept IsExists `xml:"accept,omitempty"`
		Reject IsExists `xml:"reject,omitempty"`
		Next   String   `xml:"next,omitempty"`
	} `xml:"then,omitempty"`
	Term PolicyStatementTerm `xml:"term,omitempty"`
}
type RoutingOptions *struct {
	ConfigElementFlags
	RouterId         String `xml:"router-id,omitempty"`
	AutonomousSystem *struct {
		ConfigElementFlags
		ASNumber Int `xml:"as-number,omitempty"`
	} `xml:"autonomous-system,omitempty"`
	Static *struct {
		ConfigElementFlags
		Route []struct {
			ConfigElementFlags
			Name          String   `xml:"name,omitempty"`
			NextTable     String   `xml:"next-table,omitempty"`
			Reject        IsExists `xml:"reject,omitempty"`
			NoReadvertise IsExists `xml:"no-readvertise,omitempty"`
			Preference    *struct {
				ConfigElementFlags
				MetricValue Int `xml:"metric-value,omitempty"`
			} `xml:"preference,omitempty"`
		} `xml:"route,omitempty"`
	} `xml:"static,omitempty"`
	InstanceImport []String `xml:"instance-import,omitempty"`
	InstanceExport []String `xml:"instance-export,omitempty"`
}
type Protocols *struct {
	ConfigElementFlags
	BGP *struct {
		ConfigElementFlags
		PathSelection *struct {
			ConfigElementFlags
			AlwaysCompareMed IsExists `xml:"always-compare-med,omitempty"`
		} `xml:"path-selection,omitempty"`
		Group []struct {
			ConfigElementFlags
			Name      String `xml:"name,omitempty"`
			Type      String `xml:"type,omitempty"`
			Multipath *struct {
				ConfigElementFlags
				MultipleAS IsExists `xml:"multiple-as,omitempty"`
			} `xml:"multipath,omitempty"`
			Neighbor []struct {
				ConfigElementFlags
				Name         String   `xml:"name,omitempty"`
				Description  String   `xml:"description,omitempty"`
				LocalAddress String   `xml:"local-address,omitempty"`
				Import       []String `xml:"import,omitempty"`
				Export       []String `xml:"export,omitempty"`
				PeerAS       String   `xml:"peer-as,omitempty"`
			} `xml:"neighbor,omitempty"`
		} `xml:"group,omitempty"`
		PrecisionTimers IsExists `xml:"precision-timers,omitempty"`
		HoldTime        IsExists `xml:"hold-time,omitempty"`
		LogUpdown       IsExists `xml:"log-updown,omitempty"`
	} `xml:"bgp,omitempty"`
}
type Access *struct {
	ConfigElementFlags
	AddressAssignment *struct {
		Pool []struct {
			ConfigElementFlags
			Name   String `xml:"name,omitempty"`
			Family *struct {
				ConfigElementFlags
				INet *struct {
					ConfigElementFlags
					Network String `xml:"network,omitempty"`
					Range   []struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
						Low  String `xml:"low,omitempty"`
						High String `xml:"high,omitempty"`
					} `xml:"range,omitempty"`
					DHCPAttributes *struct {
						ConfigElementFlags
						NameServer []struct {
							ConfigElementFlags
							Name String `xml:"name,omitempty"`
						} `xml:"name-server,omitempty"`
						Router []struct {
							ConfigElementFlags
							Name String `xml:"name,omitempty"`
						} `xml:"router,omitempty"`
					} `xml:"dhcp-attributes,omitempty"`
					Host []struct {
						ConfigElementFlags
						Name            String `xml:"name,omitempty"`
						HardwareAddress String `xml:"hardware-address,omitempty"`
						IPAddress       String `xml:"ip-address,omitempty"`
					} `xml:"host,omitempty"`
				} `xml:"inet,omitempty"`
			} `xml:"family,omitempty"`
		} `xml:"pool,omitempty"`
	} `xml:"address-assignment,omitempty"`
}
type SystemServicesDHCPLocalServer *struct {
	ConfigElementFlags
	Group *struct {
		ConfigElementFlags
		Name      String `xml:"name,omitempty"`
		Interface []struct {
			ConfigElementFlags
			Name String `xml:"name,omitempty"`
		} `xml:"interface,omitempty"`
	} `xml:"group,omitempty"`
}
type ForwardingOptions *struct {
	ConfigElementFlags
	DHCPRelay *struct {
		ConfigElementFlags
		ServerGroup *struct {
			ConfigElementFlags
			ServerGroup []struct {
				ConfigElementFlags
				Name    String `xml:"name,omitempty"`
				Address []struct {
					ConfigElementFlags
					Name String `xml:"name,omitempty"`
				} `xml:"address,omitempty"`
			} `xml:"server-group,omitempty"`
		} `xml:"server-group,omitempty"`
		Group *struct {
			ConfigElementFlags
			Name              String `xml:"name,omitempty"`
			ActiveServerGroup []struct {
				ConfigElementFlags
				ActiveServerGroup String   `xml:"active-server-group,omitempty"`
				AllowServerChange IsExists `xml:"allow-server-change,omitempty"`
			} `xml:"active-server-group,omitempty"`
			Interface []struct {
				ConfigElementFlags
				Name String `xml:"name,omitempty"`
			} `xml:"interface,omitempty"`
		} `xml:"group,omitempty"`
	} `xml:"dhcp-relay,omitempty"`
}
type IKEIdentity *struct {
	ConfigElementFlags
	Hostname *struct {
		ConfigElementFlags
		IdentityHostname String `xml:"identity-hostname,omitempty"`
	} `xml:"hostname,omitempty"`
}

type AUXPortConfiguration *struct {
	ConfigElementFlags
	LogOutOnDisconnect IsExists `xml:"log-out-on-disconnect,omitempty"`
	Insecure           IsExists `xml:"insecure,omitempty"`
	Type               String   `xml:"type,omitempty"`
}
type AUXPortAuthentication *struct {
	ConfigElementFlags
	EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
}
type SSHPublicKeyName []struct {
	ConfigElementFlags
	Name SSHPubKey `xml:"name,omitempty"`
}
type UserAuthentication *struct {
	ConfigElementFlags
	EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
	SSHRSA            SSHPublicKeyName  `xml:"ssh-rsa,omitempty"`
	SSHECDSA          SSHPublicKeyName  `xml:"ssh-ecdsa,omitempty"`
}
