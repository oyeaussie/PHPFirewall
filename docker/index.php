<?php

include '../vendor/autoload.php';

$response = [];

if (!isset($_GET['ip'])) {
    $response['code'] = 1;

    $response['message'] = 'Please provide ip address in the query string.';
} else {
    try {
        $firewall = new \PHPFirewall\Firewall;

        $response['code'] = 0;

        $response['allowed'] = $firewall->checkIp($_GET['ip']);

        $response['details'] = $firewall->response->getAllData();

        $response['lookup_details'] = $firewall->getProcessedMicroTimers();
    } catch (\throwable $e) {
        $response['code'] = 1;

        $response['message'] = 'Error processing request. Please contact developer.';
    }
}

echo json_encode($response);