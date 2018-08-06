# **WMI network detection rules**

## **Credits**
Jaco Blokker (KPN) <br>
Bouke van Laethem (KPN-CERT) <br>
Andre Oosterwijk (KPN-CERT) <br>

## **Context and approach**
Lateral movement is a very hot topic, especially with the offensive side of Cyber security. There is a reasonable amount of research on the defensive side, but it mostly focuses on lateral movement detection on endpoints. To fill the gap with regards to network level detection, last year we started to look into this at KPN. The resulting network detection rules help our detection and response capabilities. Additionally, they give us a better understanding of our networks (while at the same time being fun to research, make and tweak). One use-case for these rules is a situation where EDR capabilities are rare or hard to implement.

#### These rules were developed with these objectives in mind in advance:
*	Detection of WMI usage attempts too, not just WMI in action. And for both passed and failed attempts. When these rules fire, you could consider this as 'early warning' indicators.
*	Provision of possible traces/evidence of which identity or credentials were used. This would enable better follow up, like analysis by security analysts and incident responders.
*	Provision insight in what was carried out (remote execution of commands, query or data exfiltration)

#### Testing of rules was conducted across multiple combinations of client and server OS's:
*	Server side: windows releases (windows 2012 R2, windows 2016, Windows 10 pro)
*	Used clients: windows 7, windows 10, Debian linux with latest package 'impacket' available from https://github.com/CoreSecurity/impacket. See examples section; wmiexec, wmiquery
*	Detection via Snort IDS: current version, 2.9.11.1, with default configuration and custom rules.

#### Remaining issues (please help and share improvements):
*	The dce modifier in the bytetest keyword (f.e. as used in the 'RPC access denied rule'). So current rule does not take auto-detect into account of the used endianness. A re-run with snort compiled in debugging mode (using snort_pp_debug, dce2_debug, snort_debug) directives presented more insight info, however it did not provide a clue so far. Might be a misinterpretation on our side?
* 	Use of encryption on rpc level (auth level “auth priv”) leads to false negatives on the early warning rules. Even detection of 'generic' type of 'remote activation' call failed.

## **Recommended usage**
These rules are 'policy' based. This means the variables used should match traffic patterns in the network and should exclude the already so called "known-good traffic". These rules are not useful for detection of vulnerabilities and exploits. Our approach is to use whitelisting of sources and destinations from/to/between which WMI traffic is expected and working our way down the list of unknowns, until no more unknowns exist.

You are welcome to submit feedback and to contribute improvements by contacting cert(at)kpn-cert.nl.

## **WMI in action - rules**

The overview below summarizes a selection of rules developed with description (desc), and assesses the false positive (FP)/false negative(FN) rate.

*alert tcp !legitimate_sources any -> $your_protected_assets 135  (msg:"Request for WMI interface IWbemLevel1Login - indicator user connecting [MS-WMI 3.1.4.1]"; flow:to_server,established; dce_iface:F309AD18-D86A-11d0-A075-00C04FB68820; tag:session,exclusive; reference:url, https://msdn.microsoft.com/en-us/library/cc250739.aspx;  metadata:service dcerpc;  classtype:policy-violation;  sid:4103022; rev:1; )*
 - `desc:`	attempts to detect WMI handshaking, i.e. a user connecting to the management services interface in an particular namespace.  Captures additional traffic voor current session for analysis and response (see objectives)
 - `FP:`	not known.
 - `FN:`	not known.

*alert tcp !legitimate_sources any -> $your_protected_assets 135  (msg:"Request for WMI query results [MS-WMI 3.1.4.4]"; flow:to_server,established; dce_iface:027947e1-d731-11ce-a357-000000000001; metadata:service dcerpc;  reference:url, https://msdn.microsoft.com/enus/library/cc250793.aspx; classtype:policy-violation; sid:4103020; rev:1; )*
 - `desc:`	attempts to detect enumerating of common information model (CIM) objects
 - `FP:`	not known.
 - `FN:`	yes, for native WMI (windows) clients. Using 'impacket' did fire alerts though.

*alert tcp !legitimate_sources any -> $your_protected_assets 135   (msg:"Request for interface IWebmServices - indicator remote WMI query or exec [MS-WMI 3.1.4.3]"; flow:to_server,established; dce_iface:9556dc99-828c-11cf-a37e-00aa003240c7; reference: url, https://msdn.microsoft.com/en-us/library/cc250780.aspx; metadata:service dcerpc;  classtype:policy-violation; sid:4103023; rev:1;)*
 - `desc:`	attempts to detect remote execution or remote querying. See Microsoft's documentation for an extensive list of opnums (methods) and it's meaning that are exposed by this interface
 - `FP:`	not known.
 - `FN:`	yes, for native WMI (windows) clients, using impackets did fire alerts though.

#### # Early warning  - rules. The rules are supposed to be used in conjunction with each other.

*alert tcp !legitimate_sources any -> $your_protected_assets  135  (msg:"RPC remote activation of WMI [MS-DCOM 3.1.2.5.2.2]"; flow:to_server,established; dce_iface:000001a0-0000-0000-c000-000000000046; content:"|5e f0 c3 8b 6b d8 d0 11 a0 75 00 c0 4f b6 88 20|"; flowbits:set,wmi_remoteactivation_attempt; metadata:service dcerpc; reference:url, https://msdn.microsoft.com/en-us/library/cc226958.aspx; classtype:policy-violation; sid:4103001; rev:2; )*
 - `desc:`	this rule attempts to detect activation of the WMI classobject as denoted by GUID (UUID) 8BC3F05E-D86B-11D0-A075-00C04FB68820. The GUID is passed as context in the request. This translates into the raw byte sequence as can read from the rule.
 - `FP:`	not known at this time.
 - `FN:`	yes, when auth encryption "packet privacy" is used.
                      
*alert tcp $your_protected_assets any 135  -> !legitimate_sources any (msg:"RPC access denied in WMI session initialisation"; flow:to_client, established; flowbits:isset,wmi_remoteactivation_attempt; content:"|05 00 03|"; offset:0; depth:3; byte_test:4,=,0x00000005,24,little; metadata:service dcerpc; classtype:policy-violation; sid:4103009; rev:2; )*
 - `desc:`	attempt to detect a RPC PDU "fault" type. If for the same session, a WMI initialization was observed, this rule would fire.
 - `FP:`	yes, as a RPC session represented by a (tcp) stream may share several context ID's, this rule does not account for that. It might be that the reject response refers to another call than the WMI startup call
 - `FN:`	not known. Endianess is manually set to Little endian. The preferred way is to have the dcerpc2 preprocessor handle this.
 
*alert tcp $your_protected_assets any 135  -> !legitimate_sources any (msg:"RPC generic access denied"; flow:to_client, established; flowbits:isnotset,wmi_remoteactivation_attempt; content:"|05 00 03|"; offset:0; depth:3; byte_test:4,=,0x00000005,24,little; metadata:service dcerpc; classtype:policy-violation; sid:4103005; rev:2; )*
 - `desc:`	if the more specific rule (the former one) does not match, and if match for the same established session, then alert
 - `FP:` 	not known.
 - `FN:` 	see remaining issues
 
#### # Generic activation of remote objects
*alert tcp $your_protected_assets any 135  -> !legitimate_sources any  (msg:"RPC request generic remote activation”;  flow:to_server,established;  dce_iface:000001a0-0000-0000-c000-000000000046;metadata:service dcerpc;   reference: url, https://msdn.microsoft.com/en-us/library/cc226958.aspx; classtype:policy-violation; sid:4103004; rev:4;)*
 - `desc:`	generic rule for detecting activation of remote objects
 - `FP:`	High. By nature, any alarms triggered could mean WMI over RPC usage, but other remote objects as well. Depending on your policy, just RPC traffic could be already suspicious.
 - `FN:`	Yes, if WMI session is setup using auth method "packet privacy" (for other levels this might be the same )
