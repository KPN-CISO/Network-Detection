# WMI network detection rules
Author: Andre Oosterwijk

## Context
Already a lot has been published on detecting lateral movement on endpoint level. There is actually limited research on lateral movement detection on a network level. At KPN we started to look into this last year. Yes it is fun to break things apart, but mainly because we believe network detection rules are valuable for detection & response capabilities. These rules are especially valuable for example in case there are a endpoints in the network where EDR capabilities are rare are hard to implement. And therefore visibility on an endpoint level is low.

## Recommended usage
These rules are 'policy' based. So this means that the variables used should match traffic patterns in the network and should exclude the already so called "known-traffic".
These rules are not useful for detection of vulnerabilities and exploits.

### Rules
1. [WMI OXID](1. WMI rule OXID.txt)

 - dce_iface:99fcfec4-5260-101b-bbcb-00aa0021347a	(GUID for OXID resolver) <br>
**Note:** OXID interface is part of DCOM, not specific to WMI. Because most of WMI traffic is using DCOM/RPC you would expect traffic on the OXID interface. 
But there are WMI variants that does not trigger on OXID traffic, so there is a chance for false negatives.
So a hit on an 'OXID rule' COULD indicate that WMI is involved. But it's not necessarily the case (other legit applications could use remote DCOM as well)
Although it is at least suspicious if DCOM related traffic is initiated from a client to a server.


 - metadata:service dcerpc	(match for all DCERPC detected streams, on all ports) <br>
**Note:** DCOM uses RPC for transport. Windows uses connection oriented (TCP) RPC by default. Initially traffic routes over port 135, but later in a session it switches to srcport >1024 -> dstport >1024

2. [WMI NTLMlogin](2. WMI rule NTLMLogin.txt)


 - dce_iface:F309AD18-D86A-11d0-A075-00C04FB68820	(GUID for IWbemLevel1Login interface, typical pattern for the start of a "WMI handshake/session")

 - dce_opnum:6	[Method for calling NTLMlogin, Mandatory according to the specifications)

 - tag:session,600,seconds,0,packets	(if there is a match capture traffic of the whole session, no limits, maximum of 10 minutes)

 - classtype: policy-violation	(attempted-admin could also be chosen as classtype if admin or service credentials are involved)
