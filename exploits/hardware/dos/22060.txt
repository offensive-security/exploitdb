source: https://www.securityfocus.com/bid/6297/info

It has been reported that the ftpd server, included in the Embedded Real Time Operating System (ERTOS) of 3Com Superstack 3 NBX IP phones, contains a denial of service vulnerability. This issue can be triggered by sending a CEL paramater of excessive length, effectively causing the ftpd server and various VoIP services to no longer respond.

It should be noted that this issue may be similar to the vulnerability described in BID 679.

Although unconfirmed, it should also be noted that due to the nature of this vulnerability under some circumstances it may be exploited to execute arbitrary code.

CEL aaaa[...]aaaa where string is 2048 bytes long