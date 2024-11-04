## Awards
PHPFirewall was awarded 1st prize in the IP2Location Programming Contest 2024
[IP2Location Programming Contest 2024](https://contest.ip2location.com/winners)

## Description:
PHPFirewall is a tool to allow/block connections to your web resource using IP address. The IP address details are either retrieved from local database or by making API calls to IP2Location.io

## Why this project?
Internet is ever growing. New devices are coming online everyday which requires the ISPs to add new network range into their system. This makes it quite difficult for firewalls like Cisco or pfsense (linux) to manage policies or know about all networks that are introduced by the ISP of a particular region. Most network hacking happens because of incorrect/failed firewall rules. It's just hard to know all of the network IP ranges of a region.

I wanted to create a firewall application that can be installed on shared hosting, that does not require physical access to the hardware or require a dedicated hardware to run. PHPFirewall can run in a shared hosting environment like Cpanel and it will work just fine. Most Cpanel providers provide access to the users space via SSH, so managing the firewall via CLI is possible.

The whole idea is not to worry about which IP belongs to which part of the world. 1 line should be enough to allow connection from that region and the firewall should take care of the rest of the connections by blocking them. 
Ip2location.io API along with this application - PHPFirewall, makes this possible. 

## Code Example:
```php
//In index.php
<?php

include 'vendor/autoload.php';

//At this point, we assume that firewall configuration and/or IP2location API keys are set!
if (!(new \PHPFirewall\Firewall)->checkIp()) {
    //Send 404
    http_response_code(404);
    exit;
}

// Rest of your code
```

## Documentation:

[Documentation for this repository](https://github.com/oyeaussie/PHPFirewall/wiki/1.-Description)

## Credits:
Thanks to the following projects for their great work. Without them, this project would not be possible.<br>

Composer<br>
Symphony Http Foundation<br>
Ip2location.io - https://www.ip2location.io/<br>
Ip2location PHP Module - https://github.com/chrislim2888/IP2Location-PHP-Module<br>
Ip2location Proxy PHP Module - https://github.com/ip2location/ip2proxy-php<br>
Guzzle - https://github.com/guzzle/guzzle<br>
Flysystem - https://github.com/thephpleague/flysystem<br>
SleekDB - https://github.com/SleekDB/SleekDB<br>
The PHP League CSV - https://github.com/thephpleague/csv<br>
Carbon Date : https://carbon.nesbot.com/<br>
Codeception : https://codeception.com/<br>
PHPUnit : https://phpunit.de/<br>

## Issues/Discussions/New features:
Feel free to open an issue in case of a bug or to discuss anything related to the tool or to add a new feature.

## Buy Me A Coffee/Beer:
Time is valuable. If you feel this project has been helpful and it has saved your time worth a coffee or a beer...<br><br>
<a href="https://www.buymeacoffee.com/oyeaussie" target="_blank"><img src="https://github.com/oyeaussie/assets/blob/main/buymecoffee.jpg" alt="Buy Me A Coffee"></a>
<a href="https://github.com/sponsors/oyeaussie?frequency=one-time&sponsor=oyeaussie&amount=10" target="_blank"><img src="https://github.com/oyeaussie/assets/blob/main/buymebeer.jpg" alt="Buy Me A Beer"></a>

## Hire me:
If you would like to develop a PHP application that requires expert level programming. I am available for hire. Message me and we can discuss further.

## Repo Activity:

![Repo Activity](https://repobeats.axiom.co/api/embed/b697a39a301be8feae16fcdf29cb428864b7188b.svg "Repo Activity")
