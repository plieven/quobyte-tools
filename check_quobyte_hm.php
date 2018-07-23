#!/usr/bin/php -q
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
              'method' => 'getHealthManagerStatus',
              'params' => array('retry' => 'INTERACTIVE'),
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

$system_health = $result['result']['health_manager_status']['system_health'];
if (!$system_health) {
    print "UNKNOWN Could not retrieve system_health\n";
    exit(3);
}

if ($system_health == 'HEALTHY') {
    print $system_health;
    exit(0);
}

print $system_health;
exit(1);

?>
