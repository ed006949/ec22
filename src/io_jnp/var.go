package io_jnp

import (
	"encoding/xml"
)

var (
	Version = &Juniper_vSRX_22{
		ConfigElementFlags: ConfigElementFlags{
			Unsupported: false,
			Inactive:    false,
			MinVersion:  "",
		},
		XMLName: xml.Name{
			Space: "",
			Local: "",
		},
		Configuration: &struct {
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
					Telnet  *struct{ ConfigElementFlags } `xml:"telnet,omitempty"`
					NetConf *struct {
						ConfigElementFlags
						SSH IsExists `xml:"ssh,omitempty"`
					} `xml:"netconf,omitempty"`
					WebManagement *struct {
						ConfigElementFlags
						HTTP  *struct{ ConfigElementFlags } `xml:"undocumented>http,omitempty"`
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
					User []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Warning   IsExists `xml:"warning,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
					} `xml:"user,omitempty"`
					Host []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
						StructuredData *struct {
							ConfigElementFlags
							Brief IsExists `xml:"brief,omitempty"`
						} `xml:"structured-data,omitempty"`
					} `xml:"host,omitempty"`
					File []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
						StructuredData *struct {
							ConfigElementFlags
							Brief IsExists `xml:"brief,omitempty"`
						} `xml:"structured-data,omitempty"`
					} `xml:"file,omitempty"`
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
			MultiChassis *struct{ ConfigElementFlags } `xml:"multi-chassis,omitempty"`
			SNMP         *struct {
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
		}{
			ConfigElementFlags: ConfigElementFlags{
				Unsupported: false,
				Inactive:    false,
				MinVersion:  "",
			},
			Version: &struct {
				ConfigElementFlags
				Value string `xml:",chardata"`
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				Value: "",
			},
			System: &struct {
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
					Telnet  *struct{ ConfigElementFlags } `xml:"telnet,omitempty"`
					NetConf *struct {
						ConfigElementFlags
						SSH IsExists `xml:"ssh,omitempty"`
					} `xml:"netconf,omitempty"`
					WebManagement *struct {
						ConfigElementFlags
						HTTP  *struct{ ConfigElementFlags } `xml:"undocumented>http,omitempty"`
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
					User []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Warning   IsExists `xml:"warning,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
					} `xml:"user,omitempty"`
					Host []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
						StructuredData *struct {
							ConfigElementFlags
							Brief IsExists `xml:"brief,omitempty"`
						} `xml:"structured-data,omitempty"`
					} `xml:"host,omitempty"`
					File []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
						StructuredData *struct {
							ConfigElementFlags
							Brief IsExists `xml:"brief,omitempty"`
						} `xml:"structured-data,omitempty"`
					} `xml:"file,omitempty"`
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				HostName: &struct {
					ConfigElementFlags
					Value string `xml:",chardata"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Value: "",
				},
				RootAuthentication: &struct {
					ConfigElementFlags
					EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
					SSHRSA            SSHPublicKeyName  `xml:"ssh-rsa,omitempty"`
					SSHECDSA          SSHPublicKeyName  `xml:"ssh-ecdsa,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					EncryptedPassword: &struct {
						ConfigElementFlags
						Value string `xml:",chardata"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Value: "",
					},
					SSHRSA:   nil,
					SSHECDSA: nil,
				},
				Login: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					RetryOptions: &struct {
						ConfigElementFlags
						TriesBeforeDisconnect Int `xml:"tries-before-disconnect,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						TriesBeforeDisconnect: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
					},
					User: nil,
					Password: &struct {
						ConfigElementFlags
						MinimumLength Int    `xml:"minimum-length,omitempty"`
						Format        String `xml:"format,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						MinimumLength: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						Format: &struct {
							ConfigElementFlags
							Value string `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: "",
						},
					},
				},
				Services: &struct {
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
					Telnet  *struct{ ConfigElementFlags } `xml:"telnet,omitempty"`
					NetConf *struct {
						ConfigElementFlags
						SSH IsExists `xml:"ssh,omitempty"`
					} `xml:"netconf,omitempty"`
					WebManagement *struct {
						ConfigElementFlags
						HTTP  *struct{ ConfigElementFlags } `xml:"undocumented>http,omitempty"`
						HTTPS *struct {
							ConfigElementFlags
							SystemGeneratedCertificate IsExists `xml:"system-generated-certificate,omitempty"`
						} `xml:"https,omitempty"`
					} `xml:"web-management,omitempty"`
					DHCPLocalServer SystemServicesDHCPLocalServer `xml:"dhcp-local-server,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					SSH: &struct {
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
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						RootLogin: &struct {
							ConfigElementFlags
							Value string `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: "",
						},
						NoPasswordAuthentication: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						NoPasswords: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						ProtocolVersion: &struct {
							ConfigElementFlags
							Value string `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: "",
						},
						MaxSessionsPerConnection: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						SFTPServer: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						ClientAliveCountMax: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						ClientAliveInterval: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						LogKeyChanges: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						ConnectionLimit: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						RateLimit: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
					},
					Telnet: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
					NetConf: &struct {
						ConfigElementFlags
						SSH IsExists `xml:"ssh,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						SSH: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					WebManagement: &struct {
						ConfigElementFlags
						HTTP  *struct{ ConfigElementFlags } `xml:"undocumented>http,omitempty"`
						HTTPS *struct {
							ConfigElementFlags
							SystemGeneratedCertificate IsExists `xml:"system-generated-certificate,omitempty"`
						} `xml:"https,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						HTTP: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						HTTPS: &struct {
							ConfigElementFlags
							SystemGeneratedCertificate IsExists `xml:"system-generated-certificate,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							SystemGeneratedCertificate: &struct{ ConfigElementFlags }{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
							},
						},
					},
					DHCPLocalServer: &struct {
						ConfigElementFlags
						Group *struct {
							ConfigElementFlags
							Name      String `xml:"name,omitempty"`
							Interface []struct {
								ConfigElementFlags
								Name String `xml:"name,omitempty"`
							} `xml:"interface,omitempty"`
						} `xml:"group,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Group: &struct {
							ConfigElementFlags
							Name      String `xml:"name,omitempty"`
							Interface []struct {
								ConfigElementFlags
								Name String `xml:"name,omitempty"`
							} `xml:"interface,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Name: &struct {
								ConfigElementFlags
								Value string `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: "",
							},
							Interface: nil,
						},
					},
				},
				DomainName: &struct {
					ConfigElementFlags
					Value string `xml:",chardata"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Value: "",
				},
				TimeZone: &struct {
					ConfigElementFlags
					Value TimeZoneValue `xml:",chardata"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Value: TimeZoneValue{},
				},
				DefaultAddressSelection: &struct{ ConfigElementFlags }{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
				},
				ManagementInstance: &struct{ ConfigElementFlags }{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
				},
				InternetOptions: &struct {
					ConfigElementFlags
					SourcePort *struct {
						ConfigElementFlags
						UpperLimit Int `xml:"upper-limit,omitempty"`
					} `xml:"source-port,omitempty"`
					TCPMSS Int `xml:"tcp-mss,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					SourcePort: &struct {
						ConfigElementFlags
						UpperLimit Int `xml:"upper-limit,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						UpperLimit: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
					},
					TCPMSS: &struct {
						ConfigElementFlags
						Value int `xml:",chardata"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Value: 0,
					},
				},
				Ports: &struct {
					ConfigElementFlags
					Console   AUXPortConfiguration `xml:"console,omitempty"`
					Auxiliary AUXPortConfiguration `xml:"auxiliary,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Console: &struct {
						ConfigElementFlags
						LogOutOnDisconnect IsExists `xml:"log-out-on-disconnect,omitempty"`
						Insecure           IsExists `xml:"insecure,omitempty"`
						Type               String   `xml:"type,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						LogOutOnDisconnect: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						Insecure: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						Type: &struct {
							ConfigElementFlags
							Value string `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: "",
						},
					},
					Auxiliary: &struct {
						ConfigElementFlags
						LogOutOnDisconnect IsExists `xml:"log-out-on-disconnect,omitempty"`
						Insecure           IsExists `xml:"insecure,omitempty"`
						Type               String   `xml:"type,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						LogOutOnDisconnect: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						Insecure: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						Type: &struct {
							ConfigElementFlags
							Value string `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: "",
						},
					},
				},
				DiagPortAuthentication: &struct {
					ConfigElementFlags
					EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					EncryptedPassword: &struct {
						ConfigElementFlags
						Value string `xml:",chardata"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Value: "",
					},
				},
				PicConsoleAuthentication: &struct {
					ConfigElementFlags
					EncryptedPassword EncryptedPassword `xml:"encrypted-password,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					EncryptedPassword: &struct {
						ConfigElementFlags
						Value string `xml:",chardata"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Value: "",
					},
				},
				NameServer: nil,
				Syslog: &struct {
					ConfigElementFlags
					Archive *struct {
						ConfigElementFlags
						Size            SiInt    `xml:"size,omitempty"`
						Files           Int      `xml:"files,omitempty"`
						NoWorldReadable IsExists `xml:"no-world-readable,omitempty"`
						NoBinaryData    IsExists `xml:"no-binary-data,omitempty"`
					} `xml:"archive,omitempty"`
					User []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Warning   IsExists `xml:"warning,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
					} `xml:"user,omitempty"`
					Host []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
						StructuredData *struct {
							ConfigElementFlags
							Brief IsExists `xml:"brief,omitempty"`
						} `xml:"structured-data,omitempty"`
					} `xml:"host,omitempty"`
					File []struct {
						ConfigElementFlags
						Name     String `xml:"name,omitempty"`
						Contents []struct {
							ConfigElementFlags
							Name      String   `xml:"name,omitempty"`
							Any       IsExists `xml:"any,omitempty"`
							Notice    IsExists `xml:"notice,omitempty"`
							Emergency IsExists `xml:"emergency,omitempty"`
						} `xml:"contents,omitempty"`
						StructuredData *struct {
							ConfigElementFlags
							Brief IsExists `xml:"brief,omitempty"`
						} `xml:"structured-data,omitempty"`
					} `xml:"file,omitempty"`
					TimeFormat *struct {
						ConfigElementFlags
						Year        IsExists `xml:"year,omitempty"`
						Millisecond IsExists `xml:"millisecond,omitempty"`
					} `xml:"time-format,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Archive: &struct {
						ConfigElementFlags
						Size            SiInt    `xml:"size,omitempty"`
						Files           Int      `xml:"files,omitempty"`
						NoWorldReadable IsExists `xml:"no-world-readable,omitempty"`
						NoBinaryData    IsExists `xml:"no-binary-data,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Size: &struct {
							ConfigElementFlags
							Value SiIntValue `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						Files: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						NoWorldReadable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						NoBinaryData: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					User: nil,
					Host: nil,
					File: nil,
					TimeFormat: &struct {
						ConfigElementFlags
						Year        IsExists `xml:"year,omitempty"`
						Millisecond IsExists `xml:"millisecond,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Year: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						Millisecond: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
				},
				CompressConfigurationFiles: &struct{ ConfigElementFlags }{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
				},
				MaxConfigurationsOnFlash: &struct {
					ConfigElementFlags
					Value int `xml:",chardata"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Value: 0,
				},
				MaxConfigurationRollbacks: &struct {
					ConfigElementFlags
					Value int `xml:",chardata"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Value: 0,
				},
				Archival: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Configuration: &struct {
						ConfigElementFlags
						TransferOnCommit IsExists `xml:"transfer-on-commit,omitempty"`
						ArchiveSites     []struct {
							ConfigElementFlags
							Name     String   `xml:"name,omitempty"`
							Password Password `xml:"password,omitempty"`
						} `xml:"archive-sites,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						TransferOnCommit: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						ArchiveSites: nil,
					},
				},
				Processes: &struct {
					ConfigElementFlags
					DaemonProcess []struct {
						ConfigElementFlags
						Name    String   `xml:"name,omitempty"`
						Disable IsExists `xml:"disable,omitempty"`
					} `xml:"daemon-process,omitempty"`
					SMTPDservice IsDisable `xml:"smtpd-service,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					DaemonProcess: nil,
					SMTPDservice: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
				},
				NTP: &struct {
					ConfigElementFlags
					Server []struct {
						ConfigElementFlags
						Name String `xml:"name,omitempty"`
					} `xml:"server,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Server: nil,
				},
			},
			Chassis: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				CraftLockout: &struct{ ConfigElementFlags }{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
				},
				ConfigButton: &struct {
					ConfigElementFlags
					NoRescue IsExists `xml:"no-rescue,omitempty"`
					NoClear  IsExists `xml:"no-clear,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					NoRescue: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
					NoClear: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
				},
				Cluster: &struct {
					ConfigElementFlags
					UseActualMacOnPhysicalInterfaces IsExists `xml:"use-actual-mac-on-physical-interfaces,omitempty"`
					UseActiveChildMacOnReth          IsExists `xml:"use-active-child-mac-on-reth,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					UseActualMacOnPhysicalInterfaces: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
					UseActiveChildMacOnReth: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
				},
			},
			Services: &struct {
				ConfigElementFlags
				ApplicationIdentification *struct {
					ConfigElementFlags
					NoApplicationIdentification IsExists `xml:"undocumented>no-application-identification,omitempty"`
				} `xml:"application-identification,omitempty"`
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				ApplicationIdentification: &struct {
					ConfigElementFlags
					NoApplicationIdentification IsExists `xml:"undocumented>no-application-identification,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					NoApplicationIdentification: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
				},
			},
			Security: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				KeyProtection: &struct{ ConfigElementFlags }{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
				},
				IKE: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Traceoptions: &struct {
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
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						File: &struct {
							Filename        String   `xml:"filename,omitempty"`
							Size            SiInt    `xml:"size,omitempty"`
							Files           Int      `xml:"files,omitempty"`
							NoWorldReadable IsExists `xml:"no-world-readable,omitempty"`
						}{
							Filename: &struct {
								ConfigElementFlags
								Value string `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: "",
							},
							Size: &struct {
								ConfigElementFlags
								Value SiIntValue `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: 0,
							},
							Files: &struct {
								ConfigElementFlags
								Value int `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: 0,
							},
							NoWorldReadable: &struct{ ConfigElementFlags }{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
							},
						},
						Flag: &struct {
							ConfigElementFlags
							Name String `xml:"name,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Name: &struct {
								ConfigElementFlags
								Value string `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: "",
							},
						},
					},
					RespondBadSPI: &struct {
						ConfigElementFlags
						MaxResponses Int `xml:"max-responses,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						MaxResponses: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
					},
					Proposal: nil,
					Policy:   nil,
					Gateway:  nil,
				},
				IPSec: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Traceoptions: &struct {
						ConfigElementFlags
						Flag *struct {
							ConfigElementFlags
							Name String `xml:"name,omitempty"`
						} `xml:"flag,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Flag: &struct {
							ConfigElementFlags
							Name String `xml:"name,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Name: &struct {
								ConfigElementFlags
								Value string `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: "",
							},
						},
					},
					VPNMonitorOptions: &struct {
						ConfigElementFlags
						Interval  Int `xml:"interval,omitempty"`
						Threshold Int `xml:"threshold,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Interval: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
						Threshold: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
					},
					Proposal: nil,
					Policy:   nil,
					VPN:      nil,
				},
				AddressBook: nil,
				ALG: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					DNS: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					FTP: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					H323: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					MGCP: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					MSRPC: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					SunRPC: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					RSH: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					RTSP: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					SCCP: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					SIP: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					SQL: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					Talk: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					TFTP: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					PPTP: &struct {
						ConfigElementFlags
						Disable IsExists `xml:"disable,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Disable: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
				},
				ApplicationTracking: &struct {
					ConfigElementFlags
					Disable IsExists `xml:"disable,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Disable: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
				},
				Flow: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					AllowDNSReply: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
					AllowEmbeddedICMP: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
					TCPMSS: &struct {
						ConfigElementFlags
						AllTCP   FlowMSS `xml:"all-tcp,omitempty"`
						IPSecVPN FlowMSS `xml:"ipsec-vpn,omitempty"`
						GREIn    FlowMSS `xml:"gre-in,omitempty"`
						GREOut   FlowMSS `xml:"gre-out,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						AllTCP: &struct {
							ConfigElementFlags
							MSS Int `xml:"mss,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							MSS: &struct {
								ConfigElementFlags
								Value int `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: 0,
							},
						},
						IPSecVPN: &struct {
							ConfigElementFlags
							MSS Int `xml:"mss,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							MSS: &struct {
								ConfigElementFlags
								Value int `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: 0,
							},
						},
						GREIn: &struct {
							ConfigElementFlags
							MSS Int `xml:"mss,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							MSS: &struct {
								ConfigElementFlags
								Value int `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: 0,
							},
						},
						GREOut: &struct {
							ConfigElementFlags
							MSS Int `xml:"mss,omitempty"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							MSS: &struct {
								ConfigElementFlags
								Value int `xml:",chardata"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								Value: 0,
							},
						},
					},
					TCPSession: &struct {
						ConfigElementFlags
						NoSynCheck         IsExists `xml:"no-syn-check,omitempty"`
						NoSynCheckInTunnel IsExists `xml:"no-syn-check-in-tunnel,omitempty"`
						NoSequenceCheck    IsExists `xml:"no-sequence-check,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						NoSynCheck: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						NoSynCheckInTunnel: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
						NoSequenceCheck: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					ForceIPReassembly: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
				},
				Screen: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Trap: &struct {
						ConfigElementFlags
						Interval Int `xml:"interval,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Interval: &struct {
							ConfigElementFlags
							Value int `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: 0,
						},
					},
					IDSOption: nil,
				},
				NAT: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Source: &struct {
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
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						RuleSet: nil,
					},
				},
				Policies: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Policy: nil,
					DefaultPolicy: &struct {
						ConfigElementFlags
						PermitAll IsExists `xml:"permit-all,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						PermitAll: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
				},
				Zones: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					FunctionalZone: &struct {
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
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Management: &struct {
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
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							HostInboundTraffic: &struct {
								ConfigElementFlags
								SystemServices []struct {
									ConfigElementFlags
									Name String `xml:"name,omitempty"`
								} `xml:"system-services,omitempty"`
								Protocols []struct {
									ConfigElementFlags
									Name String `xml:"name,omitempty"`
								} `xml:"protocols,omitempty"`
							}{
								ConfigElementFlags: ConfigElementFlags{
									Unsupported: false,
									Inactive:    false,
									MinVersion:  "",
								},
								SystemServices: nil,
								Protocols:      nil,
							},
						},
					},
					SecurityZone: nil,
				},
			},
			Interfaces: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				Interface: nil,
			},
			MultiChassis: &struct{ ConfigElementFlags }{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
			},
			SNMP: &struct {
				ConfigElementFlags
				Interface String `xml:"interface,omitempty"`
				Community []struct {
					ConfigElementFlags
					Name          String `xml:"name,omitempty"`
					Authorization String `xml:"authorization,omitempty"`
				} `xml:"community,omitempty"`
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				Interface: &struct {
					ConfigElementFlags
					Value string `xml:",chardata"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Value: "",
				},
				Community: nil,
			},
			PolicyOptions: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				PrefixList:      nil,
				PolicyStatement: nil,
			},
			RoutingInstances: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				Instance: nil,
			},
			Protocols: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				BGP: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					PathSelection: &struct {
						ConfigElementFlags
						AlwaysCompareMed IsExists `xml:"always-compare-med,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						AlwaysCompareMed: &struct{ ConfigElementFlags }{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
						},
					},
					Group: nil,
					PrecisionTimers: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
					HoldTime: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
					LogUpdown: &struct{ ConfigElementFlags }{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
					},
				},
			},
			RoutingOptions: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				RouterId: &struct {
					ConfigElementFlags
					Value string `xml:",chardata"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Value: "",
				},
				AutonomousSystem: &struct {
					ConfigElementFlags
					ASNumber Int `xml:"as-number,omitempty"`
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					ASNumber: &struct {
						ConfigElementFlags
						Value int `xml:",chardata"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Value: 0,
					},
				},
				Static: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					Route: nil,
				},
				InstanceImport: nil,
				InstanceExport: nil,
			},
			ForwardingOptions: &struct {
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
			}{
				ConfigElementFlags: ConfigElementFlags{
					Unsupported: false,
					Inactive:    false,
					MinVersion:  "",
				},
				DHCPRelay: &struct {
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
				}{
					ConfigElementFlags: ConfigElementFlags{
						Unsupported: false,
						Inactive:    false,
						MinVersion:  "",
					},
					ServerGroup: &struct {
						ConfigElementFlags
						ServerGroup []struct {
							ConfigElementFlags
							Name    String `xml:"name,omitempty"`
							Address []struct {
								ConfigElementFlags
								Name String `xml:"name,omitempty"`
							} `xml:"address,omitempty"`
						} `xml:"server-group,omitempty"`
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						ServerGroup: nil,
					},
					Group: &struct {
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
					}{
						ConfigElementFlags: ConfigElementFlags{
							Unsupported: false,
							Inactive:    false,
							MinVersion:  "",
						},
						Name: &struct {
							ConfigElementFlags
							Value string `xml:",chardata"`
						}{
							ConfigElementFlags: ConfigElementFlags{
								Unsupported: false,
								Inactive:    false,
								MinVersion:  "",
							},
							Value: "",
						},
						ActiveServerGroup: nil,
						Interface:         nil,
					},
				},
			},
		},
	}
)
