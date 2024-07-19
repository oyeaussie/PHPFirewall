<?php

namespace PHPFirewall;

use Carbon\Carbon;
use PHPFirewall\Base;
use Phalcon\Filter\Validation\Validator\Ip;
use Symfony\Component\HttpFoundation\IpUtils;

class Firewall extends Base
{
    public function __construct($createRoot = false, $dataPath = null)
    {
        parent::__construct($createRoot, $dataPath);
    }

    public function getFirewallConfig()
    {
        unset($this->config['_id']);

        $this->addResponse('Ok', 0, $this->config);

        return (array) $this->response;
    }

    public function getFilters()
    {
        $filters = $this->firewallFiltersStore->findAll();

        $this->addResponse('Ok', 0, ['filters' => $filters], true);

        return (array) $this->response;
    }
}