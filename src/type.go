package main

import (
	"encoding/xml"

	"ec22/src/l"
)

type xmlConf struct {
	XMLName xml.Name          `xml:"conf"`
	Daemon  *l.ControlType    `xml:"daemon,omitempty"`
	Storage []*XMLConfStorage `xml:"storages>storage,omitempty"`
}

type XMLConfStorage struct {
	Name string `xml:"name,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
	Path string `xml:"path,attr,omitempty"`
}

type TrueIfExists bool
type SiValue int

type JNPConfigFlags struct {
	Unsupported TrueIfExists `xml:"unsupported,attr,omitempty"`
	Inactive    TrueIfExists `xml:"inactive,attr,omitempty"`
}

type jnpConf struct {
	JNPConfigFlags
	XMLName       xml.Name
	Configuration *struct {
		JNPConfigFlags
		Version String `xml:"version,omitempty"`
		System  *struct {
			JNPConfigFlags
			HostName           String `xml:"host-name,omitempty"`
			RootAuthentication *struct {
				JNPConfigFlags
				EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
				SSHRSA            []struct {
					JNPConfigFlags
					Name SSHPubKey `xml:"name,omitempty"`
				} `xml:"ssh-rsa,omitempty"`
			} `xml:"root-authentication,omitempty"`
			Login *struct {
				JNPConfigFlags
				RetryOptions *struct {
					JNPConfigFlags
					TriesBeforeDisconnect Int `xml:"tries-before-disconnect,omitempty"`
				} `xml:"retry-options,omitempty"`
				User *struct {
					JNPConfigFlags
					Name           String `xml:"name,omitempty"`
					UID            Int    `xml:"uid,omitempty"`
					Class          String `xml:"class,omitempty"`
					Authentication *struct {
						JNPConfigFlags
						EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
						SSHRSA            []struct {
							JNPConfigFlags
							Name SSHPubKey `xml:"name,omitempty"`
						} `xml:"ssh-rsa,omitempty"`
					} `xml:"authentication,omitempty"`
				} `xml:"user,omitempty"`
				Password *struct {
					JNPConfigFlags
					MinimumLength Int    `xml:"minimum-length,omitempty"`
					Format        String `xml:"format,omitempty"`
				} `xml:"password,omitempty"`
			} `xml:"login,omitempty"`
			Services *struct {
				JNPConfigFlags
				SSH *struct {
					JNPConfigFlags
					RootLogin                String   `xml:"root-login,omitempty"`
					NoPasswordAuthentication IsExists `xml:"no-password-authentication,omitempty"`
					NoPasswords              IsExists `xml:"no-passwords,omitempty"`
					ProtocolVersion          String   `xml:"protocol-version,omitempty"`
					MaxSessionsPerConnection Int      `xml:"max-sessions-per-connection,omitempty"`
					SFTPServer               IsExists `xml:"sftp-server,omitempty"`
					ClientAliveCountMax      Int      `xml:"client-alive-count-max,omitempty"`
					ClientAliveInterval      Int      `xml:"client-alive-interval,omitempty"`
					LogKeyChanges            IsExists `xml:"log-key-changes,omitempty"`
					ConnectionLimit          Int      `xml:"connection-limit,omitempty"`
					RateLimit                Int      `xml:"rate-limit,omitempty"`
				}
				Telnet *struct {
					JNPConfigFlags
				} `xml:"telnet,omitempty"`
				NetConf *struct {
					JNPConfigFlags
					SSH *struct{}
				} `xml:"netconf,omitempty"`
				WebManagement *struct {
					JNPConfigFlags
					HTTP *struct {
						JNPConfigFlags
					} `xml:"http,omitempty"`
					HTTPS *struct {
						JNPConfigFlags
						SystemGeneratedCertificate IsExists `xml:"system-generated-certificate,omitempty"`
					} `xml:"https,omitempty"`
				} `xml:"web-management,omitempty"`
			} `xml:"services,omitempty"`
			DomainName              String   `xml:"domain-name,omitempty"`
			TimeZone                TimeZone `xml:"time-zone,omitempty"`
			DefaultAddressSelection IsExists `xml:"default-address-selection,omitempty"`
			ManagementInstance      IsExists `xml:"management-instance,omitempty"`
			InternetOptions         *struct {
				JNPConfigFlags
				TCPMSS Int `xml:"tcp-mss,omitempty"`
			} `xml:"internet-options,omitempty"`
			Ports *struct {
				JNPConfigFlags
				Console *struct {
					JNPConfigFlags
					LogOutOnDisconnect IsExists `xml:"log-out-on-disconnect,omitempty"`
					Insecure           IsExists `xml:"insecure,omitempty"`
					Type               String   `xml:"type,omitempty"`
				} `xml:"console,omitempty"`
				Auxiliary *struct {
					JNPConfigFlags
					LogOutOnDisconnect IsExists `xml:"log-out-on-disconnect,omitempty"`
					Insecure           IsExists `xml:"insecure,omitempty"`
					Type               String   `xml:"type,omitempty"`
				} `xml:"auxiliary,omitempty"`
			} `xml:"ports,omitempty"`
			DiagPortAuthentication *struct {
				JNPConfigFlags
				EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
			} `xml:"diag-port-authentication,omitempty"`
			PicConsoleAuthentication *struct {
				JNPConfigFlags
				EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
			} `xml:"pic-console-authentication,omitempty"`
			NameServer []struct {
				JNPConfigFlags
				Name String `xml:"name,omitempty"`
			} `xml:"name-server,omitempty"`
			Syslog *struct {
				JNPConfigFlags
				Archive *struct {
					JNPConfigFlags
					Size            Int      `xml:"size,omitempty"`
					Files           Int      `xml:"files,omitempty"`
					NoWorldReadable IsExists `xml:"no-world-readable,omitempty"`
					NoBinaryDate    IsExists `xml:"no-binary-date,omitempty"`
				} `xml:"archive,omitempty"`
				User []struct {
					JNPConfigFlags
					Name     String `xml:"name,omitempty"`
					Contents []struct {
						JNPConfigFlags
						Name      String   `xml:"name,omitempty"`
						Any       IsExists `xml:"any,omitempty"`
						Notice    IsExists `xml:"notice,omitempty"`
						Emergency IsExists `xml:"emergency,omitempty"`
					} `xml:"contents,omitempty"`
				} `xml:"user,omitempty"`
				Host []struct {
					JNPConfigFlags
					Name     String `xml:"name,omitempty"`
					Contents []struct {
						JNPConfigFlags
						Name      String   `xml:"name,omitempty"`
						Any       IsExists `xml:"any,omitempty"`
						Notice    IsExists `xml:"notice,omitempty"`
						Emergency IsExists `xml:"emergency,omitempty"`
					} `xml:"contents,omitempty"`
					StructuredData *struct {
						JNPConfigFlags
						Brief IsExists `xml:"brief,omitempty"`
					} `xml:"structured-data,omitempty"`
				} `xml:"host,omitempty"`
				File []struct {
					JNPConfigFlags
					Name     String `xml:"name,omitempty"`
					Contents []struct {
						JNPConfigFlags
						Name      String   `xml:"name,omitempty"`
						Any       IsExists `xml:"any,omitempty"`
						Notice    IsExists `xml:"notice,omitempty"`
						Emergency IsExists `xml:"emergency,omitempty"`
					} `xml:"contents,omitempty"`
					StructuredData *struct {
						JNPConfigFlags
						Brief IsExists `xml:"brief,omitempty"`
					} `xml:"structured-data,omitempty"`
				} `xml:"file,omitempty"`
				TimeFormat *struct {
					JNPConfigFlags
					Year        IsExists `xml:"year,omitempty"`
					Millisecond IsExists `xml:"millisecond,omitempty"`
				} `xml:"time-format,omitempty"`
			} `xml:"syslog,omitempty"`
			CompressConfigurationFiles IsExists `xml:"compress-configuration-files,omitempty"`
			MaxConfigurationsOnFlash   Int      `xml:"max-configurations-on-flash,omitempty"`
			MaxConfigurationRollbacks  Int      `xml:"max-configuration-rollbacks,omitempty"`
			Archival                   *struct {
				JNPConfigFlags
				Configuration *struct {
					JNPConfigFlags
					TransferOnCommit IsExists `xml:"transfer-on-commit,omitempty"`
					ArchiveSites     []struct {
						JNPConfigFlags
						Name     String   `xml:"name,omitempty"`
						Password Password `xml:"password,omitempty"`
					} `xml:"archive-sites,omitempty"`
				} `xml:"configuration,omitempty"`
			} `xml:"archival,omitempty"`
			Processes *struct {
				JNPConfigFlags
				DaemonProcess []struct {
					JNPConfigFlags
					Name    String   `xml:"name,omitempty"`
					Disable IsExists `xml:"disable,omitempty"`
				} `xml:"daemon-process,omitempty"`
				SMTDPService *struct {
					JNPConfigFlags
					Disable IsExists `xml:"disable,omitempty"`
				} `xml:"smtdp-service,omitempty"`
			} `xml:"processes,omitempty"`
			NTP *struct {
				JNPConfigFlags
				Server []struct {
					JNPConfigFlags
					Name String `xml:"name,omitempty"`
				} `xml:"server,omitempty"`
			} `xml:"ntp,omitempty"`
		} `xml:"system,omitempty"`
		Chassis *struct {
			JNPConfigFlags
			CraftLockout IsExists `xml:"craft-lockout,omitempty"`
			ConfigButton *struct {
				JNPConfigFlags
				NoRescue IsExists `xml:"no-rescue,omitempty"`
				NoClear  IsExists `xml:"no-clear,omitempty"`
			} `xml:"config-button,omitempty"`
			Cluster *struct {
				JNPConfigFlags
				UseActualMacOnPhysicalInterfaces IsExists `xml:"use-actual-mac-on-physical-interfaces,omitempty"`
				UseActiveChildMacOnReth          IsExists `xml:"use-active-child-mac-on-reth,omitempty"`
			} `xml:"cluster,omitempty"`
		} `xml:"chassis,omitempty"`
		Security *struct {
			JNPConfigFlags
			KeyProtection IsExists `xml:"key-protection,omitempty"`
			IKE           *struct {
				JNPConfigFlags
				Traceoptions *struct {
					JNPConfigFlags
					Filename        String   `xml:"filename,omitempty"`
					Size            Int      `xml:"size,omitempty"`
					Files           Int      `xml:"files,omitempty"`
					NoWorldReadable IsExists `xml:"no-world-readable,omitempty"`
				} `xml:"traceoptions,omitempty"`
				Flag *struct {
					JNPConfigFlags
					Name String `xml:"name,omitempty"`
				} `xml:"flag,omitempty"`
				RespondBadSPI *struct {
					JNPConfigFlags
					MaxResponses Int `xml:"max-responses,omitempty"`
				} `xml:"respond-bad-spi,omitempty"`
				Proposal []struct {
					JNPConfigFlags
					Name                    String `xml:"name,omitempty"`
					AuthenticationMethod    String `xml:"authentication-method,omitempty"`
					DHGroup                 String `xml:"dh-group,omitempty"`
					AuthenticationAlgorithm String `xml:"authentication-algorithm,omitempty"`
					EncryptionAlgorithm     String `xml:"encryption-algorithm,omitempty"`
					LifetimeSeconds         Int    `xml:"lifetime-seconds,omitempty"`
				} `xml:"proposal,omitempty"`
				Policy []struct {
					JNPConfigFlags
					Name         String   `xml:"name,omitempty"`
					Proposals    []String `xml:"proposals,omitempty"`
					PreSharedKey *struct {
						JNPConfigFlags
						ASCIIText String `xml:"ascii-text,omitempty"`
					} `xml:"pre-shared-key,omitempty"`
				} `xml:"policy,omitempty"`
				Gateway []struct {
					JNPConfigFlags
					Name              String   `xml:"name,omitempty"`
					IKEPolicy         []String `xml:"ike-policy,omitempty"`
					Address           []String `xml:"address,omitempty"`
					DeadPeerDetection *struct {
						JNPConfigFlags
						AlwaysSend IsExists `xml:"always-send,omitempty"`
						Interval   Int      `xml:"interval,omitempty"`
						Threshold  Int      `xml:"threshold,omitempty"`
					} `xml:"dead-peer-detection,omitempty"`
					LocalIdentity *struct {
						JNPConfigFlags
						Hostname *struct {
							JNPConfigFlags
							IdentityHostname String `xml:"identity-hostname,omitempty"`
						} `xml:"hostname,omitempty"`
					} `xml:"local-identity,omitempty"`
					RemoteIdentity *struct {
						JNPConfigFlags
						Hostname *struct {
							JNPConfigFlags
							IdentityHostname String `xml:"identity-hostname,omitempty"`
						} `xml:"hostname,omitempty"`
					} `xml:"remote-identity,omitempty"`
					ExternalInterface String `xml:"external-interface,omitempty"`
					Version           String `xml:"version,omitempty"`
				} `xml:"gateway,omitempty"`
			} `xml:"ike,omitempty"`
			IPSec *struct {
				JNPConfigFlags
			} `xml:"ipsec,omitempty"`
		} `xml:"security,omitempty"`
	} `xml:"configuration,omitempty"`
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
type Int *struct {
	JNPConfigFlags
	Value SiValue `xml:",chardata"`
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
