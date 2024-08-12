<h2>Description:</h2>
PHPFirewall is a tool to allow/block connections to your web resource using IP address. The IP address details are either retrieved from local database or by making API calls to IP2Location.io

<h2>Code Example:</h2>

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

<h2>Documentation:</h2>

[Documentation for this repository](https://github.com/oyeaussie/PHPFirewall/wiki/1.-Description)

<h2>Credits:</h2>
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

<h2>Issues/Discussions/New features:</h2>
Feel free to open an issue in case of a bug or to discuss anything related to the tool or to add a new feature.

<h2>Buy Me A Coffee/Beer:</h2>
Time is valuable. If you feel this project has been helpful and it has saved your time worth a coffee or a beer...<br><br>
<a href="https://www.buymeacoffee.com/oyeaussie" target="_blank"><img src="https://github.com/oyeaussie/assets/blob/main/buymecoffee.jpg" alt="Buy Me A Coffee"></a>
<a href="https://github.com/sponsors/oyeaussie?frequency=one-time&sponsor=oyeaussie&amount=10" target="_blank"><img src="https://github.com/oyeaussie/assets/blob/main/buymebeer.jpg" alt="Buy Me A Beer"></a>

<h2>Hire me:</h2>
If you would like to develop a PHP application that requires expert level programming. I am available for hire. Message me and we can discuss further.

<h2>Repo Activity:</h2>

![Repo Activity](https://repobeats.axiom.co/api/embed/b697a39a301be8feae16fcdf29cb428864b7188b.svg "Repo Activity")