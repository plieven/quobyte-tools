<?php

if ($argc < 4) {
	print "Usage: <API> <USER> <PASSWD>\n";
	exit(2);
}

curl_setopt_array($ch = curl_init(), array(
	CURLOPT_TIMEOUT => 3,
	CURLOPT_HEADER => 0,
	CURLOPT_RETURNTRANSFER => TRUE,
	CURLOPT_URL => $argv[1],
	CURLOPT_CAINFO => "/etc/ssl/certs/ca-certificates.crt",
	CURLOPT_PROXY => '',
	CURLOPT_USERPWD => $argv[2].':'.$argv[3],
	CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
	CURLOPT_POSTFIELDS => json_encode(
		array('id' => uniqid(),
		      'jsonrpc' => '2.0',
		      'method' => 'getFiringRules',
		      'params' => array('retry' => 'NEVER'),
		)
	),
));

curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));

$result = curl_exec($ch);
if ($result === false) {
	print "JSONRPC failed\n";
	exit(3);
}
curl_close($ch);

$result = json_decode($result, true);
if ($result === false) {
	print "JSONRPC decode failed\n";
	exit(3);
}

if (array_key_exists('error', $result)) {
	print $result['error']['message']."\n";
	exit(2);
}

if (!array_key_exists('result', $result)) {
	print "UNKNOWN Error\n";
	exit(3);
}

$ret = 0;
$errors = array();

foreach ($result['result']['rule'] as $row) {
	if ($row['alert_state'] != 'FIRING') continue;
	if (array_key_exists($row['rule_identifier'], $errors)) {
		$errors[$row['rule_identifier']]++;
	} else {
		$errors[$row['rule_identifier']] = 1;
	}
	if ($row['severity'] == 'WARNING') $ret = max($ret, 1);
	if ($row['severity'] == 'ERROR') $ret = max($ret, 2);
}

foreach ($errors as $rule => $cnt) {
	print $rule.($cnt > 1 ? '('.$cnt.')' : '').' ';
}

if (!count($errors)) print "no alerts";

exit($ret);

?>
