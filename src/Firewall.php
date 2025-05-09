<?php

namespace PHPFirewall;

use Carbon\Carbon;
use PHPFirewall\Base;
use PHPFirewall\Filters;
use PHPFirewall\Geo;
use PHPFirewall\Indexes;
use PHPFirewall\Ip2location;
use PHPFirewall\Profiling;
use SleekDB\Cache;
use SleekDB\Classes\IoHelper;
use Symfony\Component\HttpFoundation\IpUtils;

class Firewall extends Base
{
    public $geo;

    public $indexes;

    public $ip2location;

    public $ip;

    public $profiling;

    public $filters;

    public function __construct($createRoot = false, $dataPath = null)
    {
        parent::__construct($createRoot, $dataPath);

        $this->geo = new Geo($this, $dataPath);

        $this->indexes = new Indexes($this, $dataPath);

        $this->ip2location = new Ip2location($this, $dataPath);

        $this->profiling = new Profiling($this);

        $this->filters = new Filters($this);
    }

    public function checkIp($ip = null, array $overrideIp2locationLookupSequence = null)
    {
        $this->getConfig();

        if ($this->config['status'] === 'disable') {
            $this->addResponse('Firewall is disabled. Everything is allowed!', 2);

            return true;
        }

        if (!$ip) {
            $ip = $this->ip2location->ipTools->getVisitorIp();
        }

        if (!$this->validateIP($ip)) {
            return false;
        }

        $this->ip = $ip;

        //Zero Check - We check Ip in Index
        $this->profiling->setMicroTimer('indexesCheckIpFilter', true, true);

        $indexes = $this->indexes->searchIndexes($ip);

        if ($indexes && is_array($indexes) && count($indexes) === 2) {
            $filter = $this->filters->getFilterById($indexes[0], false, $indexes[1]);

            if ($filter) {
                $indexesCheckIpFilter = $this->filters->checkIPFilter($filter, false, $indexes[1]);

                $this->profiling->setMicroTimer('indexesCheckIpFilter', true);

                return $indexesCheckIpFilter;
            }
        }

        //First Check - We check HOST entries
        $this->profiling->setMicroTimer('hostCheckIpFilter', true, true);

        $filter = $this->filters->getFilterByAddressAndType($ip, 'host');

        if ($filter) {//We find the address in address_type host
            $hostCheckIpFilter = $this->filters->checkIPFilter($filter, $ip);

            $this->profiling->setMicroTimer('hostCheckIpFilter', true);

            return $hostCheckIpFilter;
        }

        //Second Check - We check NETWORK entries
        $this->profiling->setMicroTimer('networkCheckIpFilter', true, true);

        $filters = $this->filters->getFilterByType('network');

        if ($filters && count($filters) > 0) {
            foreach ($filters as $filterKey => $filter) {
                if (IpUtils::checkIp($ip, $filter['address'])) {
                    $networkCheckIpFilter = $this->filters->checkIPFilter($filter, $ip);

                    $this->profiling->setMicroTimer('networkCheckIpFilter', true);

                    return $networkCheckIpFilter;
                }
            }
        }

        //Third Check - We check ip2location as per the primary set first and then secondary if we did not find the entry
        $this->profiling->setMicroTimer('ip2locationCheckIpFilter', true, true);

        $ip2locationFilters = [];

        $filters = $this->filters->getFilterByType('ip2location');

        if ($filters && count($filters) > 0) {
            foreach ($filters as $filterKey => $filter) {

                $ip2locationAddressArr = explode(':', $filter['address']);

                if (count($ip2locationAddressArr) === 1) {
                    $ip2locationFilters[$ip2locationAddressArr[0]]['id'] = $filter['id'];
                } else if (count($ip2locationAddressArr) === 2) {
                    $ip2locationFilters[$ip2locationAddressArr[0]][$ip2locationAddressArr[1]]['id'] = $filter['id'];
                } else if (count($ip2locationAddressArr) === 3) {
                    $ip2locationFilters[$ip2locationAddressArr[0]][$ip2locationAddressArr[1]][$ip2locationAddressArr[2]]['id'] = $filter['id'];
                }
            }
        }

        if (count($ip2locationFilters) > 0) {
            $ip2locationLookupOptions = ['API', 'BIN'];

            if ($overrideIp2locationLookupSequence && count($overrideIp2locationLookupSequence) === 2) {
                $ip2locationLookupOptions = $overrideIp2locationLookupSequence;
            }

            if (in_array($this->config['ip2location_primary_lookup_method'], $ip2locationLookupOptions)) {
                if (!$overrideIp2locationLookupSequence) {
                    $arrayKey = array_keys($ip2locationLookupOptions, $this->config['ip2location_primary_lookup_method']);

                    $ip2locationLookupOptionsMethod = strtoupper($ip2locationLookupOptions[$arrayKey[0]]);
                } else {
                    $ip2locationLookupOptionsMethod = strtoupper($ip2locationLookupOptions[0]);
                }

                $lookupMethod = 'getIpDetailsFromIp2location' . $ip2locationLookupOptionsMethod;

                $response = $this->ip2location->$lookupMethod($ip);

                if (!$response) {//Not found in primary lookup, we get the secondary from list.
                    unset($ip2locationLookupOptions[$arrayKey[0]]);

                    $ip2locationLookupOptions = array_values($ip2locationLookupOptions);

                    $ip2locationLookupOptionsMethod = strtoupper($ip2locationLookupOptions[0]);

                    $lookupMethod = 'getIpDetailsFromIp2location' . $ip2locationLookupOptionsMethod;

                    $response = $this->ip2location->$lookupMethod($ip);
                }

                if ($response) {
                    $filterRule = null;

                    if (isset($ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])][strtolower($response['city_name'])]['id'])) {
                        $filterRule = $ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])][strtolower($response['city_name'])]['id'];
                    } else if (isset($ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])]['id'])) {
                        $filterRule = $ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])]['id'];
                    } else if (isset($ip2locationFilters[strtolower($response['country_code'])]['id'])) {
                        $filterRule = $ip2locationFilters[strtolower($response['country_code'])]['id'];
                    }

                    if ($filterRule) {
                        $filter = $this->filters->getFilterById($filterRule);

                        if (isset($filter['ip2location_proxy']) && $filter['ip2location_proxy'] === 'block') {
                            if (isset($response['is_proxy']) && $response['is_proxy'] === true) {
                                $filter['filter_type'] = 'block';
                            }
                        }

                        $ip2locationCheckIpFilter = $this->filters->checkIPFilter($filter, $ip);

                        $this->profiling->setMicroTimer('ip2location' . $ip2locationLookupOptionsMethod . 'CheckIpFilter', true);

                        return $ip2locationCheckIpFilter;
                    }
                }
            }
        }

        //Forth - We check DEFAULT entries
        $this->profiling->setMicroTimer('defaultCheckIpFilter', true, true);

        $this->config['default_filter_hit_count'] = (int) $this->config['default_filter_hit_count'] + 1;

        $this->updateConfig($this->config);

        //We check host entry in the default store
        $filter = $this->filters->getFilterByAddressAndType($ip, 'host', true);

        if ($filter) {//We find the address in default store and bump its counter
            $this->filters->bumpFilterHitCounter($filter, true);

            $this->indexes->addToIndex($filter, true);//Add to index
        } else {//We add a new entry in default store
            $newFilter['address_type'] = 'host';
            $newFilter['address'] = $ip;
            $newFilter['hit_count'] = 1;
            $newFilter['updated_by'] = "000";
            $newFilter['updated_at'] = time();
            $newFilter['filter_type'] = $this->config['default_filter'];
            $filter = $this->filters->addFilter($newFilter, true);
        }

        $this->profiling->setMicroTimer('defaultCheckIpFilter', true);

        if ($this->config['default_filter'] === 'allow') {
            $this->addResponse('Allowed', 0, ['default_filter' => true, 'filter' => $filter]);

            if ($this->config['log_filter_allowed'] === true) {
                $this->filterLogger->notice('ALLOWED', ['ip' => $this->ip, 'filters_store'=> 'default', 'filter_id' => $filter['id']]);
            }

            return true;
        } else if ($this->config['default_filter'] === 'block') {
            if ($this->config['status'] === 'monitor') {
                $this->addResponse('IP address is blocked, but firewall status is monitor so ip address is allowed!', 2, ['default_filter' => true, 'filter' => $filter]);

                return true;
            }

            $this->filterLogger->notice('BLOCKED', ['ip' => $this->ip, 'filters_store'=> 'default', 'filter_id' => $filter['id']]);

            $this->addResponse('Blocked', 1, ['default_filter' => true, 'filter' => $filter]);

            return false;
        }

        return true;
    }

    public function validateIP($address)
    {
        $ipv6 = false;
        if ($this->ip2location->ipTools->isIpv6($address)) {
            $ipv6 = true;
        }

        if (!$ipv6 && !$this->config['filter_ipv4']) {
            return false;
        }

        if ($ipv6 && !$this->config['filter_ipv6']) {
            return false;
        }

        if ($ipv6) {
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $this->addResponse('Please enter correct ip address', 1);

                return false;
            }
        } else {
            if (!filter_var($address, FILTER_VALIDATE_IP)) {
                $this->addResponse('Please enter correct ip address', 1);

                return false;
            }
        }

        $allow_private_range = true;
        if (array_key_exists('allow_private_range', $this->config) &&
            !is_null($this->config['allow_private_range']) &&
            $this->config['allow_private_range'] === false
        ) {
            $allow_private_range = false;
        }

        if (!$allow_private_range) {
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
                $this->addResponse('Please enter correct ip address, private range is not allowed.', 1);

                return false;
            }
        }

        $allow_reserved_range = true;
        if (array_key_exists('allow_reserved_range', $this->config) &&
            !is_null($this->config['allow_reserved_range']) &&
            $this->config['allow_reserved_range'] === false
        ) {
            $allow_reserved_range = false;
        }

        if (!$allow_reserved_range) {
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)) {
                $this->addResponse('Please enter correct ip address, reserved range is not allowed.', 1);

                return false;
            }
        }

        return true;
    }
}