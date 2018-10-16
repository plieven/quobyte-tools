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

if (is_array($result) && array_key_exists('error', $result)) {
    print $result['error']['message']."\n";
    exit(2);
}

if (!is_array($result) || !array_key_exists('result', $result)) {
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

curl_setopt_array($ch = curl_init(), array(
   CURLOPT_TIMEOUT => 5,
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
           'method' => 'getDeviceList',
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

if (is_array($result) && array_key_exists('error', $result)) {
    print $result['error']['message']."\n";
    exit(2);
}

if (!is_array($result) || !array_key_exists('result', $result)) {
    print "UNKNOWN Error\n";
    exit(3);
}

/* switch error level to warning by default */
$exitcode = 1;

$d_unavailable = 0;
$d_offline = 0;
$d_err_hosts = [];

foreach ($result['result']['device_list']['devices'] as $row) {
    $err = 0;
    if ($row['is_empty']) continue;
    if ($row['device_status'] == 'OFFLINE') {
        $err = 1;
        $d_offline++;
    }
    if ($row['device_status'] == 'ONLINE') {
        if (is_array($row['content'])) {
            foreach ($row['content'] as $k => $row2) {
                if (!$row2['available']) {
                    $err = 1;
                    $d_unavailable++;
                }
            }
        }
    }
    if ($err) {
        $d_err_hosts[$row['host_name']] = 1;
    }
}

/* switch error level to critical if more than one device is unavailable */
if ($d_unavailable > 1) {
    $exitcode = 2;
}

/* switch error level to critical if more than one host is affected */
if (count($d_err_hosts) > 1) {
    $exitcode = 2;
}

if (count($d_err_hosts)) {
    print $system_health . ' - ' . $d_unavailable . ' non-empty devices unavailable, ' . $d_offline . ' non-empty devices offline, ' . count($d_err_hosts) . ' hosts affected';
} else {
    print $system_health;
}

exit($exitcode);

?>
