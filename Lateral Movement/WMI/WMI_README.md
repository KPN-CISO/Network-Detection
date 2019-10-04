# **WMI network detection rules**

## **Credits**
Jaco Blokker (KPN) <br>
Bouke van Laethem (KPN-CERT) <br>
Andre Oosterwijk (KPN-CERT) <br>

## **Context and approach**
Lateral movement is a very hot topic, especially with the offensive side of Cyber security. There is a reasonable amount of research on the defensive side, but it mostly focuses on lateral movement detection on endpoints. To fill the gap with regards to network level detection, we have started to look into this at KPN. The resulting network detection rules help our detection and response capabilities. Additionally, they give us a better understanding of our networks (while at the same time being fun to research, make and tweak). One use-case for these rules is a situation where EDR capabilities are rare or hard to implement.

#### These rules were developed with these objectives in mind:
*	Detection of WMI usage attempts too, not just WMI in action. Can be considered as 'early warning' indicators.
*	Provision insight in what was carried out (remote execution of commands, query or data exfiltration)

#### Testing of rules was conducted across multiple combinations of client and server OS's:
*	Server side: windows releases (windows 2012 R2, windows 2016, Windows 10 pro)
*	Used clients: windows 7, windows 10, Debian linux with latest package 'impacket' available from https://github.com/CoreSecurity/impacket. See examples section; wmiexec, wmiquery
*	Detection via Snort IDS: 2.9.12, with default configuration and custom rules.

#### Remaining issues (please help and share improvements):
*	The dce modifier in the bytetest keyword (f.e. as used in the 'RPC reject/denied rule'). So current rule does not take auto-detect into account of the used endianness. A re-run with snort compiled in debugging mode (using snort_pp_debug, dce2_debug, snort_debug) directives presented more insight info, however it did not provide a clue so far. Might be a misinterpretation on our side?


## **Recommended usage**
These rules are 'policy' based. This means the variables used should match traffic patterns in the network and should exclude the already so called "known-good traffic". These rules are not useful for detection of vulnerabilities and exploits. Our approach is to use whitelisting of sources and destinations from/to/between which WMI traffic is expected and working our way down the list of unknowns, until no more unknowns exist.

You are welcome to submit feedback and to contribute improvements by contacting cert(at)kpn-cert.nl.


