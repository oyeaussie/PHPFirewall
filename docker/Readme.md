## Docker
Docker image for phpfirewall is available on docker hub. Run command

```console
docker run -d --name phpfirewall -h phpfirewall oyeaussie/phpfirewall
# GRAB IP
docker exec phpfirewall cat /etc/hosts | grep phpfirewall
# OUTPUT
# {container IP}    phpfirewall
# Connect via ssh
# ssh -l admin -p 2233 {container IP}
# username & password is admin
```
* ssh password can be changed via passwd command inside the docker image. Run the following commands to change the admin username password of the docker image.

```console
docker exec -it phpfirewall sh
passwd admin
```

* After logging in via SSH, you will be asked to put another login and password for PHPTerminal Auth Plugin.The login and password for auth plugin is admin. You will be asked to change the password after successful login

* Docker image also has a webserver running that can check ip via this link:

*http://{container IP}/index.php?ip={your_ip_to_check}*

#### *See index.php in the docker folder for how the server will respond*


## Example of client querying the firewall
```php
<?php

use GuzzleHttp\Client;

include 'vendor/autoload.php';

try {
    $client = new Client;

    $res = $client->request('GET', 'http://{container_ip}/index.php', [
        'query' => ['ip' => 'your_ip_to_check']
    ]);

    if ($res->getStatusCode() === 200) {
        $response = $res->getBody()->getContents();

        if ($response) {
            $response = @json_decode($response, true);

            if ($response['allowed'] === false) {
                //Send 404
                http_response_code(404);
                exit;
            }
        }
    }
} catch (\throwable $e) {
    echo $e->getMessage();
}

//Rest of your code
//Will only be available if ip is allowed or the client will be sent 404 not found.
```