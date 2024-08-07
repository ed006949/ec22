package io_jnp

import (
	"encoding/xml"
)

type TrueIfExists bool
type SiValue int

type JNPConfigFlags struct {
	Unsupported TrueIfExists `xml:"unsupported,attr,omitempty"`
	Inactive    TrueIfExists `xml:"inactive,attr,omitempty"`
}

type Node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Content []byte     `xml:",innerxml"`
	Nodes   []Node     `xml:",any"`
}

type IsExists *struct {
	JNPConfigFlags
}
type SiInt *struct {
	JNPConfigFlags
	Value SiValue `xml:",chardata"`
}
type Int *struct {
	JNPConfigFlags
	Value int `xml:",chardata"`
}
type String *struct {
	JNPConfigFlags
	Value string `xml:",chardata"`
}
type Name *struct {
	JNPConfigFlags
	Value string `xml:"name,omitempty"`
}

type EncryptedPassword *struct {
	JNPConfigFlags
	Value string `xml:",chardata"`
}
type Password *struct {
	JNPConfigFlags
	Value string `xml:",chardata"`
}
type TimeZone *struct {
	JNPConfigFlags
	Value string `xml:",chardata"`
}
type SSHPubKey *struct {
	JNPConfigFlags
	Value string `xml:",chardata"`
}

type ALG *struct {
	JNPConfigFlags
	Disable IsExists `xml:"disable,omitempty"`
}
type FlowMSS *struct {
	JNPConfigFlags
	MSS Int `xml:"mss,omitempty"`
}
type PolicyStatementTerm []struct {
	JNPConfigFlags
	Name String `xml:"name,omitempty"`
	From struct {
		JNPConfigFlags
		Protocol         []String `xml:"protocol,omitempty"`
		RouteType        []String `xml:"route-type,omitempty"`
		Instance         []String `xml:"instance,omitempty"`
		PrefixListFilter []struct {
			JNPConfigFlags
			ListName String   `xml:"list_name,omitempty"`
			Exact    IsExists `xml:"exact,omitempty"`
			Longer   IsExists `xml:"longer,omitempty"`
			Orkonger IsExists `xml:"orlonger,omitempty"`
		} `xml:"prefix-list-filter,omitempty"`
	} `xml:"from,omitempty"`
	Then *struct {
		JNPConfigFlags
		LoadBalance *struct {
			JNPConfigFlags
			PerPacket IsExists `xml:"per-packet,omitempty"`
		} `xml:"load-balance,omitempty"`
		Metric *struct {
			JNPConfigFlags
			Add    Int `xml:"add,omitempty"`
			Metric Int `xml:"metric,omitempty"`
		} `xml:"metric,omitempty"`
		NextHop *struct {
			JNPConfigFlags
			Self IsExists `xml:"self,omitempty"`
		} `xml:"next-hop,omitempty"`
		Accept IsExists `xml:"accept,omitempty"`
		Reject IsExists `xml:"reject,omitempty"`
		Next   String   `xml:"next,omitempty"`
	} `xml:"then,omitempty"`
	Term PolicyStatementTerm `xml:"term,omitempty"`
}
type RoutingOptions *struct {
	JNPConfigFlags
	RouterId         String `xml:"router-id,omitempty"`
	AutonomousSystem *struct {
		JNPConfigFlags
		ASNumber Int `xml:"as-number,omitempty"`
	} `xml:"autonomous-system,omitempty"`
	InstanceExport []String `xml:"instance-export,omitempty"`
	InstanceImport []String `xml:"instance-import,omitempty"`
	Static         *struct {
		JNPConfigFlags
		Route []struct {
			JNPConfigFlags
			Name          String   `xml:"name,omitempty"`
			NextTable     String   `xml:"next-table,omitempty"`
			Reject        IsExists `xml:"reject,omitempty"`
			NoReadvertise IsExists `xml:"no-readvertise,omitempty"`
			Preference    *struct {
				JNPConfigFlags
				MetricValue Int `xml:"metric-value,omitempty"`
			} `xml:"preference,omitempty"`
		} `xml:"route,omitempty"`
	} `xml:"static,omitempty"`
}
type Protocols *struct {
	JNPConfigFlags
	BGP *struct {
		JNPConfigFlags
		PathSelection *struct {
			JNPConfigFlags
			AlwaysCompareMed IsExists `xml:"always-compare-med,omitempty"`
		} `xml:"path-selection,omitempty"`
		Group []struct {
			JNPConfigFlags
			Name      String `xml:"name,omitempty"`
			Type      String `xml:"type,omitempty"`
			Multipath *struct {
				JNPConfigFlags
				MultipleAS IsExists `xml:"multiple-as,omitempty"`
			} `xml:"multipath,omitempty"`
			Neighbor []struct {
				JNPConfigFlags
				Name         String   `xml:"name,omitempty"`
				Description  String   `xml:"description,omitempty"`
				LocalAddress String   `xml:"local-address,omitempty"`
				Import       []String `xml:"import,omitempty"`
				Export       []String `xml:"export,omitempty"`
				PeerAS       String   `xml:"peer-as,omitempty"`
			} `xml:"neighbor,omitempty"`
			PrecisionTimers IsExists `xml:"precision-timers,omitempty"`
			HoldTime        IsExists `xml:"hold-time,omitempty"`
			LogUpdown       IsExists `xml:"log-updown,omitempty"`
		} `xml:"group,omitempty"`
	} `xml:"bgp,omitempty"`
}
type Access *struct {
	JNPConfigFlags
	AddressAssignment *struct {
		Pool []struct {
			JNPConfigFlags
			Name   String `xml:"name,omitempty"`
			Family *struct {
				JNPConfigFlags
				INet *struct {
					JNPConfigFlags
					Network String `xml:"network,omitempty"`
					Range   []struct {
						JNPConfigFlags
						Name String `xml:"name,omitempty"`
						Low  String `xml:"low,omitempty"`
						High String `xml:"high,omitempty"`
					} `xml:"range,omitempty"`
					DHCPAttributes *struct {
						JNPConfigFlags
						NameServer []struct {
							JNPConfigFlags
							Name String `xml:"name,omitempty"`
						} `xml:"name-server,omitempty"`
						Router []struct {
							JNPConfigFlags
							Name String `xml:"name,omitempty"`
						} `xml:"router,omitempty"`
					} `xml:"dhcp-attributes,omitempty"`
					Host []struct {
						JNPConfigFlags
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
	JNPConfigFlags
	Group *struct {
		JNPConfigFlags
		Name      String `xml:"name,omitempty"`
		Interface []struct {
			JNPConfigFlags
			Name String `xml:"name,omitempty"`
		} `xml:"interface,omitempty"`
	} `xml:"group,omitempty"`
}
type ForwardingOptions *struct {
	JNPConfigFlags
	DHCPRelay *struct {
		JNPConfigFlags
		ServerGroup *struct {
			JNPConfigFlags
			ServerGroup []struct {
				JNPConfigFlags
				Name    String `xml:"name,omitempty"`
				Address []struct {
					JNPConfigFlags
					Name String `xml:"name,omitempty"`
				} `xml:"address,omitempty"`
			} `xml:"server-group,omitempty"`
		} `xml:"server-group,omitempty"`
		Group *struct {
			JNPConfigFlags
			Name              String `xml:"name,omitempty"`
			ActiveServerGroup []struct {
				JNPConfigFlags
				ActiveServerGroup String   `xml:"active-server-group,omitempty"`
				AllowServerChange IsExists `xml:"allow-server-change,omitempty"`
			} `xml:"active-server-group,omitempty"`
			Interface []struct {
				JNPConfigFlags
				Name String `xml:"name,omitempty"`
			} `xml:"interface,omitempty"`
		} `xml:"group,omitempty"`
	} `xml:"dhcp-relay,omitempty"`
}
type IKEIdentity *struct {
	JNPConfigFlags
	Hostname *struct {
		JNPConfigFlags
		IdentityHostname String `xml:"identity-hostname,omitempty"`
	} `xml:"hostname,omitempty"`
}

type AUXPort *struct {
	JNPConfigFlags
	LogOutOnDisconnect IsExists `xml:"log-out-on-disconnect,omitempty"`
	Insecure           IsExists `xml:"insecure,omitempty"`
	Type               String   `xml:"type,omitempty"`
}
type AUXAuth *struct {
	JNPConfigFlags
	EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
}
type SSHPublicKey []struct {
	JNPConfigFlags
	Name SSHPubKey `xml:"name,omitempty"`
}
type UserAuthentication *struct {
	JNPConfigFlags
	EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
	SSHRSA            SSHPublicKey      `xml:"ssh-rsa,omitempty"`
	SSHECDSA          SSHPublicKey      `xml:"ssh-ecdsa,omitempty"`
}
