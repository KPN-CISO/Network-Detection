# WMI network detection rules

## Credits
Jaco Blokker (KPN)
Bouke van Laethem (KPN-CERT)
Andre Oosterwijk (KPN-CERT)

## Context
Lateral movement is a very hot topic, especially with the offensive side of Cyber security. There is a reasonable amount of research on the offensive side, but it mostly focuses on lateral movement detection on endpoints. To fill the gap with regards to network level detection, last year we started to look into this at KPN. The resulting network detection rules help our detection and response capabilities. Additionally, they give us a better understanding of our networks (while at the same time being fun to research, make and tweak). One use-case for these rules is a situation where EDR capabilities for endpoints are rare or hard to implement.

## Recommended usage
These rules are 'policy' based. This means the variables used should match traffic patterns in the network and should exclude the already so called "known-good traffic". These rules are not useful for detection of vulnerabilities and exploits. Our approach is to use whitelisting of sources and destinations from/to/between which WMI traffic is expected and working our way down the list of unknowns, until no more unknowns exist.  

### Rules

#### [WMI OXID](1.WMI_rule_OXID.txt)

 - `dce_iface:99fcfec4-5260-101b-bbcb-00aa0021347a`	(GUID for OXID resolver)
   **Note:** OXID interface is part of DCOM, not specific to WMI. Because most of WMI traffic is using DCOM/RPC you would expect traffic on the OXID interface.  But there are WMI variants that do not trigger on OXID traffic, so there is a chance for false negatives. A hit on an 'OXID rule' COULD indicate that WMI is involved. But it's not necessarily the case (other legit applications could use remote DCOM as well). Although it is at least suspicious if DCOM related traffic is initiated from a client to a server.

 - `metadata:service dcerpc`	(match for all DCERPC detected streams, on all ports) 

   **Note:** DCOM uses RPC for transport. Windows uses connection oriented (TCP) RPC by default. Initially traffic routes over port 135, but later in a session it switches to  srcport>1024 -> dstport >1024


#### [WMI NTLMlogin](2.WMI_rule_NTLMLogin.txt)

 - `dce_iface:F309AD18-D86A-11d0-A075-00C04FB68820`	(GUID for IWbemLevel1Login interface, typical pattern for the start of a "WMI handshake/session")
 - `dce_opnum:6`	[Method for calling NTLMlogin, Mandatory according to the specifications)
   tag:session,600,seconds,0,packets	(if there is a match: capture traffic of the whole session, no limits, maximum of 10 minutes)
   classtype: policy-violation	(attempted-admin could also be chosen as classtype if admin or service credentials are involved)
