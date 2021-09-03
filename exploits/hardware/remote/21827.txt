source: https://www.securityfocus.com/bid/5780/info

It has been reported that the Compaq Insight Manager web interface is prone to cross-site scripting attacks. It is possible to construct a malicious link to a Compaq Insight Manager web interface that includes arbitrary script code. When the link is visited with a web client, the script code will execute in the context of the Compaq Insight Manager web interface.

The component which appears to be affected is Compaq Insight Management Agents. However, further details about which software is vulnerable are not available.

http://<Server IP>:2301/<script>alert('Test')</script>