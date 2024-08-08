package io_jnp

import (
	"encoding/xml"
)

// Juniper - Junos map
type Juniper struct {
	EX struct {
	}
	SRX struct {
		V12_1 struct{ Conf *Juniper_vSRX_22 }
		V12_4 struct{ Conf *Juniper_vSRX_22 }
		V20   struct{ Conf *Juniper_vSRX_22 }
		V22   struct{ Conf *Juniper_vSRX_22 }
	}
	VSRX struct {
		V20 struct{ Conf *Juniper_vSRX_22 }
		V22 struct{ Conf *Juniper_vSRX_22 }
	}
}

type Juniper_vSRX_22 struct {
	ConfigElementFlags
	XMLName       xml.Name
	Configuration *struct {
		ConfigElementFlags
		Version String `xml:"version,omitempty"`
		System  *struct {
			ConfigElementFlags
			HostName           String             `xml:"host-name,omitempty"`
			RootAuthentication UserAuthentication `xml:"root-authentication,omitempty"`
			Login              *struct {
				ConfigElementFlags
				RetryOptions *struct {
					ConfigElementFlags
					TriesBeforeDisconnect Int `xml:"tries-before-disconnect,omitempty"`
				} `xml:"retry-options,omitempty"`
				User []struct {
					ConfigElementFlags
					Name           String             `xml:"name,omitempty"`
					UId            Int                `xml:"uid,omitempty"`
					Class          String             `xml:"class,omitempty"`
					Authentication UserAuthentication `xml:"authentication,omitempty"`
				} `xml:"user,omitempty"`
				Password *struct {
					ConfigElementFlags
					MinimumLength Int    `xml:"minimum-length,omitempty"`
					Format        String `xml:"format,omitempty"`
				} `xml:"password,omitempty"`
			} `xml:"login,omitempty"`
			Services *struct {
				ConfigElementFlags
				SSH *struct {
					ConfigElementFlags
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
				} `xml:"ssh,omitempty"`
				Telnet *struct {
					ConfigElementFlags
				} `xml:"telnet,omitempty"`
				NetConf *struct {
					ConfigElementFlags
					SSH IsExists `xml:"ssh,omitempty"`
				} `xml:"netconf,omitempty"`
				WebManagement *struct {
					ConfigElementFlags
					HTTP *struct {
						ConfigElementFlags
					} `xml:"undocumented>http,omitempty"`
					HTTPS *struct {
						ConfigElementFlags
						SystemGeneratedCertificate IsExists `xml:"system-generated-certificate,omitempty"`
					} `xml:"https,omitempty"`
				} `xml:"web-management,omitempty"`
				DHCPLocalServer SystemServicesDHCPLocalServer `xml:"dhcp-local-server,omitempty"`
			} `xml:"services,omitempty"`
			DomainName              String   `xml:"domain-name,omitempty"`
			TimeZone                TimeZone `xml:"time-zone,omitempty"`
			DefaultAddressSelection IsExists `xml:"default-address-selection,omitempty"`
			ManagementInstance      IsExists `xml:"management-instance,omitempty"`
			InternetOptions         *struct {
				ConfigElementFlags
				SourcePort *struct {
					ConfigElementFlags
					UpperLimit Int `xml:"upper-limit,omitempty"`
				} `xml:"source-port,omitempty"`
				TCPMSS Int `xml:"tcp-mss,omitempty"`
			} `xml:"internet-options,omitempty"`
			Ports *struct {
				ConfigElementFlags
				Console   AUXPortConfiguration `xml:"console,omitempty"`
				Auxiliary AUXPortConfiguration `xml:"auxiliary,omitempty"`
			} `xml:"ports,omitempty"`
			DiagPortAuthentication   AUXPortAuthentication `xml:"diag-port-authentication,omitempty"`
			PicConsoleAuthentication AUXPortAuthentication `xml:"pic-console-authentication,omitempty"`
			NameServer               []struct {
				ConfigElementFlags
				Name String `xml:"name,omitempty"`
			} `xml:"name-server,omitempty"`
			Syslog *struct {
				ConfigElementFlags
				Archive *struct {
					ConfigElementFlags
					Size            SiInt    `xml:"size,omitempty"`
					Files           Int      `xml:"files,omitempty"`
					NoWorldReadable IsExists `xml:"no-world-readable,omitempty"`
					NoBinaryData    IsExists `xml:"no-binary-data,omitempty"`
				} `xml:"archive,omitempty"`
				User       SyslogTargets `xml:"user,omitempty"`
				Host       SyslogTargets `xml:"host,omitempty"`
				File       SyslogTargets `xml:"file,omitempty"`
				TimeFormat *struct {
					ConfigElementFlags
					Year        IsExists `xml:"year,omitempty"`
					Millisecond IsExists `xml:"millisecond,omitempty"`
				} `xml:"time-format,omitempty"`
			} `xml:"syslog,omitempty"`
			CompressConfigurationFiles IsExists `xml:"compress-configuration-files,omitempty"`
			MaxConfigurationsOnFlash   Int      `xml:"max-configurations-on-flash,omitempty"`
			MaxConfigurationRollbacks  Int      `xml:"max-configuration-rollbacks,omitempty"`
			Archival                   *struct {
				ConfigElementFlags
				Configuration *struct {
					ConfigElementFlags
					TransferOnCommit IsExists `xml:"transfer-on-commit,omitempty"`
					ArchiveSites     []struct {
						ConfigElementFlags
						Name     String   `xml:"name,omitempty"`
						Password Password `xml:"password,omitempty"`
					} `xml:"archive-sites,omitempty"`
				} `xml:"configuration,omitempty"`
			} `xml:"archival,omitempty"`
			Processes *struct {
				ConfigElementFlags
				DaemonProcess []struct {
					ConfigElementFlags
					Name    String   `xml:"name,omitempty"`
					Disable IsExists `xml:"disable,omitempty"`
				} `xml:"daemon-process,omitempty"`
				SMTPDservice IsDisable `xml:"smtpd-service,omitempty"`
			} `xml:"processes,omitempty"`
			NTP *struct {
				ConfigElementFlags
				Server []struct {
					ConfigElementFlags
					Name String `xml:"name,omitempty"`
				} `xml:"server,omitempty"`
			} `xml:"ntp,omitempty"`
		} `xml:"system,omitempty"`
		Chassis *struct {
			ConfigElementFlags
			CraftLockout IsExists `xml:"craft-lockout,omitempty"`
			ConfigButton *struct {
				ConfigElementFlags
				NoRescue IsExists `xml:"no-rescue,omitempty"`
				NoClear  IsExists `xml:"no-clear,omitempty"`
			} `xml:"config-button,omitempty"`
			Cluster *struct {
				ConfigElementFlags
				UseActualMacOnPhysicalInterfaces IsExists `xml:"use-actual-mac-on-physical-interfaces,omitempty"`
				UseActiveChildMacOnReth          IsExists `xml:"use-active-child-mac-on-reth,omitempty"`
			} `xml:"cluster,omitempty"`
		} `xml:"chassis,omitempty"`
		Services *struct {
			ConfigElementFlags
			ApplicationIdentification *struct {
				ConfigElementFlags
				NoApplicationIdentification IsExists `xml:"undocumented>no-application-identification,omitempty"`
			} `xml:"application-identification,omitempty"`
		} `xml:"services,omitempty"`
		Security *struct {
			ConfigElementFlags
			KeyProtection IsExists `xml:"undocumented>key-protection,omitempty"`
			IKE           *struct {
				ConfigElementFlags
				Traceoptions *struct {
					ConfigElementFlags
					File *struct {
						Filename        String   `xml:"filename,omitempty"`
						Size            SiInt    `xml:"size,omitempty"`
						Files           Int      `xml:"files,omitempty"`
						NoWorldReadable IsExists `xml:"no-world-readable,omitempty"`
					} `xml:"file,omitempty"`
					Flag *struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
					} `xml:"flag,omitempty"`
				} `xml:"traceoptions,omitempty"`
				RespondBadSPI *struct {
					ConfigElementFlags
					MaxResponses Int `xml:"max-responses,omitempty"`
				} `xml:"respond-bad-spi,omitempty"`
				Proposal []struct {
					ConfigElementFlags
					Name                    String `xml:"name,omitempty"`
					AuthenticationMethod    String `xml:"authentication-method,omitempty"`
					DHGroup                 String `xml:"dh-group,omitempty"`
					AuthenticationAlgorithm String `xml:"authentication-algorithm,omitempty"`
					EncryptionAlgorithm     String `xml:"encryption-algorithm,omitempty"`
					LifetimeSeconds         Int    `xml:"lifetime-seconds,omitempty"`
				} `xml:"proposal,omitempty"`
				Policy []struct {
					ConfigElementFlags
					Name         String   `xml:"name,omitempty"`
					Proposals    []String `xml:"proposals,omitempty"`
					PreSharedKey *struct {
						ConfigElementFlags
						ASCIIText String `xml:"ascii-text,omitempty"`
					} `xml:"pre-shared-key,omitempty"`
				} `xml:"policy,omitempty"`
				Gateway []struct {
					ConfigElementFlags
					Name              String   `xml:"name,omitempty"`
					IKEPolicy         []String `xml:"ike-policy,omitempty"`
					Address           []String `xml:"address,omitempty"`
					DeadPeerDetection *struct {
						ConfigElementFlags
						AlwaysSend IsExists `xml:"always-send,omitempty"`
						Interval   Int      `xml:"interval,omitempty"`
						Threshold  Int      `xml:"threshold,omitempty"`
					} `xml:"dead-peer-detection,omitempty"`
					LocalIdentity     IKEIdentity `xml:"local-identity,omitempty"`
					RemoteIdentity    IKEIdentity `xml:"remote-identity,omitempty"`
					ExternalInterface String      `xml:"external-interface,omitempty"`
					Version           String      `xml:"version,omitempty"`
				} `xml:"gateway,omitempty"`
			} `xml:"ike,omitempty"`
			IPSec *struct {
				ConfigElementFlags
				Traceoptions *struct {
					ConfigElementFlags
					Flag *struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
					} `xml:"flag,omitempty"`
				} `xml:"traceoptions,omitempty"`
				VPNMonitorOptions *struct {
					ConfigElementFlags
					Interval  Int `xml:"interval,omitempty"`
					Threshold Int `xml:"threshold,omitempty"`
				} `xml:"vpn-monitor-options,omitempty"`
				Proposal []struct {
					ConfigElementFlags
					Name                    String `xml:"name,omitempty"`
					Protocol                String `xml:"protocol,omitempty"`
					AuthenticationAlgorithm String `xml:"authentication-algorithm,omitempty"`
					EncryptionAlgorithm     String `xml:"encryption-algorithm,omitempty"`
					LifetimeSeconds         Int    `xml:"lifetime-seconds,omitempty"`
				} `xml:"proposal,omitempty"`
				Policy []struct {
					ConfigElementFlags
					Name                  String `xml:"name,omitempty"`
					PerfectForwardSecrecy *struct {
						ConfigElementFlags
						Keys String `xml:"keys,omitempty"`
					} `xml:"perfect-forward-secrecy,omitempty"`
					Proposals []String `xml:"proposals,omitempty"`
				} `xml:"policy,omitempty"`
				VPN []struct {
					ConfigElementFlags
					Name          String `xml:"name,omitempty"`
					BindInterface String `xml:"bind-interface,omitempty"`
					DFBit         String `xml:"df-bit,omitempty"`
					IKE           *struct {
						ConfigElementFlags
						Gateway     String `xml:"gateway,omitempty"`
						IPSECPolicy String `xml:"ipsec-policy,omitempty"`
					} `xml:"ike,omitempty"`
					EstablishTunnels String `xml:"establish-tunnels,omitempty"`
				} `xml:"vpn,omitempty"`
			} `xml:"ipsec,omitempty"`
			AddressBook []struct {
				ConfigElementFlags
				Name    String `xml:"name,omitempty"`
				Address []struct {
					ConfigElementFlags
					Name     String `xml:"name,omitempty"`
					IPPrefix String `xml:"ip-prefix,omitempty"`
				} `xml:"address,omitempty"`
				AddressSet []struct {
					ConfigElementFlags
					Name    String `xml:"name,omitempty"`
					Address []struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
					} `xml:"address,omitempty"`
					AddressSet []struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
					} `xml:"address-set,omitempty"`
				} `xml:"address-set,omitempty"`
			} `xml:"address-book,omitempty"`
			ALG *struct {
				ConfigElementFlags
				DNS    IsDisable `xml:"dns,omitempty"`
				FTP    IsDisable `xml:"ftp,omitempty"`
				H323   IsDisable `xml:"h323,omitempty"`
				MGCP   IsDisable `xml:"mgcp,omitempty"`
				MSRPC  IsDisable `xml:"msrpc,omitempty"`
				SunRPC IsDisable `xml:"sunrpc,omitempty"`
				RSH    IsDisable `xml:"rsh,omitempty"`
				RTSP   IsDisable `xml:"rtsp,omitempty"`
				SCCP   IsDisable `xml:"sccp,omitempty"`
				SIP    IsDisable `xml:"sip,omitempty"`
				SQL    IsDisable `xml:"sql,omitempty"`
				Talk   IsDisable `xml:"talk,omitempty"`
				TFTP   IsDisable `xml:"tftp,omitempty"`
				PPTP   IsDisable `xml:"pptp,omitempty"`
			} `xml:"alg,omitempty"`
			ApplicationTracking IsDisable `xml:"application-tracking,omitempty"`
			Flow                *struct {
				ConfigElementFlags
				AllowDNSReply     IsExists `xml:"allow-dns-reply,omitempty"`
				AllowEmbeddedICMP IsExists `xml:"allow-embedded-icmp,omitempty"`
				TCPMSS            *struct {
					ConfigElementFlags
					AllTCP   FlowMSS `xml:"all-tcp,omitempty"`
					IPSecVPN FlowMSS `xml:"ipsec-vpn,omitempty"`
					GREIn    FlowMSS `xml:"gre-in,omitempty"`
					GREOut   FlowMSS `xml:"gre-out,omitempty"`
				} `xml:"tcp-mss,omitempty"`
				TCPSession *struct {
					ConfigElementFlags
					NoSynCheck         IsExists `xml:"no-syn-check,omitempty"`
					NoSynCheckInTunnel IsExists `xml:"no-syn-check-in-tunnel,omitempty"`
					NoSequenceCheck    IsExists `xml:"no-sequence-check,omitempty"`
				} `xml:"tcp-session,omitempty"`
				ForceIPReassembly IsExists `xml:"force-ip-reassembly,omitempty"`
			} `xml:"flow,omitempty"`
			Screen *struct {
				ConfigElementFlags
				Trap *struct {
					ConfigElementFlags
					Interval Int `xml:"interval,omitempty"`
				} `xml:"trap,omitempty"`
				IDSOption []struct {
					ConfigElementFlags
					Name String `xml:"name,omitempty"`
					ICMP *struct {
						ConfigElementFlags
						IPSweep *struct {
							ConfigElementFlags
							Threshold IsExists `xml:"threshold,omitempty"`
						} `xml:"ip-sweep,omitempty"`
						Fragment IsExists `xml:"fragment,omitempty"`
						Large    IsExists `xml:"large,omitempty"`
						Flood    *struct {
							ConfigElementFlags
							Threshold Int `xml:"threshold,omitempty"`
						} `xml:"flood,omitempty"`
						PingDeath       IsExists `xml:"ping-death,omitempty"`
						ICMPv6Malformed IsExists `xml:"icmpv6-malformed,omitempty"`
					} `xml:"icmp,omitempty"`
					IP *struct {
						ConfigElementFlags
						BadOption               IsExists `xml:"bad-option,omitempty"`
						RecordRouteOption       IsExists `xml:"record-route-option,omitempty"`
						TimestampOption         IsExists `xml:"timestamp-option,omitempty"`
						SecurityOption          IsExists `xml:"security-option,omitempty"`
						StreamOption            IsExists `xml:"stream-option,omitempty"`
						Spoofing                IsExists `xml:"spoofing,omitempty"`
						SourceRouteOption       IsExists `xml:"source-route-option,omitempty"`
						LooseSourceRouteOption  IsExists `xml:"loose-source-route-option,omitempty"`
						StrictSourceRouteOption IsExists `xml:"strict-source-route-option,omitempty"`
						UnknownProtocol         IsExists `xml:"unknown-protocol,omitempty"`
						BlockFrag               IsExists `xml:"block-frag,omitempty"`
						TearDrop                IsExists `xml:"tear-drop,omitempty"`
						IPv6MalformedHeader     IsExists `xml:"ipv6-malformed-header,omitempty"`
						Tunnel                  *struct {
							ConfigElementFlags
							BadInnerHeader IsExists `xml:"bad-inner-header,omitempty"`
							GRE            *struct {
								ConfigElementFlags
								GRE6in4 IsExists `xml:"gre-6in4,omitempty"`
								GRE4in6 IsExists `xml:"gre-4in6,omitempty"`
								GRE6in6 IsExists `xml:"gre-6in6,omitempty"`
								GRE4in4 IsExists `xml:"gre-4in4,omitempty"`
							} `xml:"gre,omitempty"`
							IPinUDP *struct {
								ConfigElementFlags
								Teredo IsExists `xml:"teredo,omitempty"`
							} `xml:"ip-in-udp,omitempty"`
							IPIP *struct {
								ConfigElementFlags
								IPIP6to4relay IsExists `xml:"ipip-6to4relay,omitempty"`
								IPIP6in4      IsExists `xml:"ipip-6in4,omitempty"`
								IPIP4in6      IsExists `xml:"ipip-4in6,omitempty"`
								IPIP6in6      IsExists `xml:"ipip-6in6,omitempty"`
								IPIP4in4      IsExists `xml:"ipip-4in4,omitempty"`
								IPIP6over4    IsExists `xml:"ipip-6over4,omitempty"`
								ISATAP        IsExists `xml:"isatap,omitempty"`
								DSLite        IsExists `xml:"dslite,omitempty"`
							} `xml:"ipip,omitempty"`
						} `xml:"tunnel,omitempty"`
					} `xml:"ip,omitempty"`
					TCP *struct {
						ConfigElementFlags
						SynFin         IsExists `xml:"syn-fin,omitempty"`
						FinNoAck       IsExists `xml:"fin-no-ack,omitempty"`
						TCPNoFlag      IsExists `xml:"tcp-no-flag,omitempty"`
						SynFrag        IsExists `xml:"syn-frag,omitempty"`
						PortScan       IsExists `xml:"port-scan,omitempty"`
						SynAckAckProxy IsExists `xml:"syn-ack-ack-proxy,omitempty"`
						SynFlood       IsExists `xml:"syn-flood,omitempty"`
						Land           IsExists `xml:"land,omitempty"`
						WinNuke        IsExists `xml:"winnuke,omitempty"`
						TCPSweep       IsExists `xml:"tcp-sweep,omitempty"`
					} `xml:"tcp,omitempty"`
					UDP *struct {
						ConfigElementFlags
						Flood    IsExists `xml:"flood,omitempty"`
						UDPSweep IsExists `xml:"udp-sweep,omitempty"`
						PortScan IsExists `xml:"port-scan,omitempty"`
					} `xml:"udp,omitempty"`
					LimitSession *struct {
						ConfigElementFlags
						SourceIPBased Int `xml:"source-ip-based,omitempty"`
					} `xml:"limit-session,omitempty"`
				} `xml:"ids-option,omitempty"`
			} `xml:"screen,omitempty"`
			NAT *struct {
				ConfigElementFlags
				Source *struct {
					ConfigElementFlags
					RuleSet []struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
						From *struct {
							ConfigElementFlags
							RoutingInstance []String `xml:"routing-instance,omitempty"`
						} `xml:"from,omitempty"`
						To *struct {
							ConfigElementFlags
							RoutingInstance []String `xml:"routing-instance,omitempty"`
						} `xml:"to,omitempty"`
						Rule []struct {
							ConfigElementFlags
							Name            String `xml:"name,omitempty"`
							SrcNATRuleMatch *struct {
								ConfigElementFlags
								SourceAddressName []String `xml:"source-address-name,omitempty"`
							} `xml:"src-nat-rule-match,omitempty"`
							Then *struct {
								ConfigElementFlags
								SourceNAT *struct {
									ConfigElementFlags
									Interface IsExists `xml:"interface,omitempty"`
								} `xml:"source-nat,omitempty"`
							} `xml:"then,omitempty"`
						} `xml:"rule,omitempty"`
					} `xml:"rule-set,omitempty"`
				} `xml:"source,omitempty"`
			} `xml:"nat,omitempty"`
			Policies *struct {
				ConfigElementFlags
				Policy []struct {
					ConfigElementFlags
					FromZoneName String `xml:"from-zone-name,omitempty"`
					ToZoneName   String `xml:"to-zone-name,omitempty"`
					Policy       []struct {
						ConfigElementFlags
						Name  String `xml:"name,omitempty"`
						Match *struct {
							ConfigElementFlags
							SourceAddress      []String `xml:"source-address,omitempty"`
							DestinationAddress []String `xml:"destination-address,omitempty"`
							Application        []String `xml:"application,omitempty"`
						} `xml:"match,omitempty"`
						Then *struct {
							ConfigElementFlags
							Permit IsExists `xml:"permit,omitempty"`
							Deny   IsExists `xml:"deny,omitempty"`
						} `xml:"then,omitempty"`
					} `xml:"policy,omitempty"`
				} `xml:"policy,omitempty"`
				DefaultPolicy *struct {
					ConfigElementFlags
					PermitAll IsExists `xml:"permit-all,omitempty"`
				} `xml:"default-policy,omitempty"`
			} `xml:"policies,omitempty"`
			Zones *struct {
				ConfigElementFlags
				FunctionalZone *struct {
					ConfigElementFlags
					Management *struct {
						ConfigElementFlags
						HostInboundTraffic *struct {
							ConfigElementFlags
							SystemServices []struct {
								ConfigElementFlags
								Name String `xml:"name,omitempty"`
							} `xml:"system-services,omitempty"`
							Protocols []struct {
								ConfigElementFlags
								Name String `xml:"name,omitempty"`
							} `xml:"protocols,omitempty"`
						} `xml:"host-inbound-traffic,omitempty"`
					} `xml:"management,omitempty"`
				} `xml:"functional-zone,omitempty"`
				SecurityZone []struct {
					ConfigElementFlags
					Name               String `xml:"name,omitempty"`
					Screen             String `xml:"screen,omitempty"`
					HostInboundTraffic *struct {
						ConfigElementFlags
						SystemServices []struct {
							ConfigElementFlags
							Name String `xml:"name,omitempty"`
						} `xml:"system-services,omitempty"`
						Protocols []struct {
							ConfigElementFlags
							Name String `xml:"name,omitempty"`
						} `xml:"protocols,omitempty"`
					} `xml:"host-inbound-traffic,omitempty"`
					Interfaces []struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
					} `xml:"interfaces,omitempty"`
				} `xml:"security-zone,omitempty"`
			} `xml:"zones,omitempty"`
		} `xml:"security,omitempty"`
		Interfaces *struct {
			ConfigElementFlags
			Interface []struct {
				ConfigElementFlags
				Name        String   `xml:"name,omitempty"`
				Description String   `xml:"description,omitempty"`
				VLANTagging IsExists `xml:"vlan-tagging,omitempty"`
				Unit        []struct {
					ConfigElementFlags
					Name        String `xml:"name,omitempty"`
					Description String `xml:"description,omitempty"`
					VLANId      Int    `xml:"vlan-id,omitempty"`
					Family      struct {
						ConfigElementFlags
						INet struct {
							ConfigElementFlags
							Address []struct {
								ConfigElementFlags
								Name String `xml:"name,omitempty"`
							} `xml:"address,omitempty"`
							DHCP *struct {
								ConfigElementFlags
								NoDNSInstall           IsExists `xml:"no-dns-install,omitempty"`
								LeaseTime              Int      `xml:"lease-time,omitempty"`
								RetransmissionAttempt  Int      `xml:"retransmission-attempt,omitempty"`
								RetransmissionInterval Int      `xml:"retransmission-interval,omitempty"`
								ForceDiscover          IsExists `xml:"force-discover,omitempty"`
								Options                []struct {
									ConfigElementFlags
									NoHostname IsExists `xml:"no-hostname,omitempty"`
								} `xml:"options,omitempty"`
							} `xml:"dhcp,omitempty"`
						} `xml:"inet,omitempty"`
					} `xml:"family,omitempty"`
				} `xml:"unit,omitempty"`
			} `xml:"interface,omitempty"`
		} `xml:"interfaces,omitempty"`
		MultiChassis *struct {
			ConfigElementFlags
		} `xml:"multi-chassis,omitempty"`
		SNMP *struct {
			ConfigElementFlags
			Interface String `xml:"interface,omitempty"`
			Community []struct {
				ConfigElementFlags
				Name          String `xml:"name,omitempty"`
				Authorization String `xml:"authorization,omitempty"`
			} `xml:"community,omitempty"`
		} `xml:"snmp,omitempty"`
		PolicyOptions *struct {
			ConfigElementFlags
			PrefixList []struct {
				ConfigElementFlags
				Name           String `xml:"name,omitempty"`
				PrefixListItem []struct {
					ConfigElementFlags
					Name String `xml:"name,omitempty"`
				} `xml:"prefix-list-item,omitempty"`
			} `xml:"prefix-list,omitempty"`
			PolicyStatement PolicyStatementTerm `xml:"policy-statement,omitempty"`
		} `xml:"policy-options,omitempty"`
		RoutingInstances *struct {
			ConfigElementFlags
			Instance []struct {
				ConfigElementFlags
				Name           String         `xml:"name,omitempty"`
				Description    String         `xml:"description,omitempty"`
				InstanceType   String         `xml:"instance-type,omitempty"`
				Protocols      Protocols      `xml:"protocols,omitempty"`
				RoutingOptions RoutingOptions `xml:"routing-options,omitempty"`
				Interface      []struct {
					ConfigElementFlags
					Name String `xml:"name,omitempty"`
				} `xml:"interface,omitempty"`
				ForwardingOptions ForwardingOptions `xml:"forwarding-options,omitempty"`
				System            *struct {
					ConfigElementFlags
					Services *struct {
						ConfigElementFlags
						DHCPLocalServer SystemServicesDHCPLocalServer `xml:"dhcp-local-server,omitempty"`
					} `xml:"services,omitempty"`
				} `xml:"system,omitempty"`
				Access Access `xml:"access,omitempty"`
			} `xml:"instance,omitempty"`
		} `xml:"routing-instances,omitempty"`
		Protocols         Protocols         `xml:"protocols,omitempty"`
		RoutingOptions    RoutingOptions    `xml:"routing-options,omitempty"`
		ForwardingOptions ForwardingOptions `xml:"forwarding-options,omitempty"`
	} `xml:"configuration,omitempty"`
}
