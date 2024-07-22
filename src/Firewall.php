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
        $this->getConfig();

        unset($this->config['_id']);

        $this->addResponse('Ok', 0, $this->config);

        return (array) $this->response;
    }

    public function getFilters($defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewallFiltersDefaultStore->findAll();
        } else {
            $filters = $this->firewallFiltersStore->findBy(['parent_id', '=', null], ['filter_type' => 'desc']);
        }

        if (count($filters) > 0) {
            if (!$defaultStore) {
                foreach ($filters as &$filter) {
                    if ($filter['address_type'] === 'host') {
                        $filter['ip_hits'] = '-';
                        continue;
                    }

                    $childs = $this->firewallFiltersStore->findBy(['parent_id', '=', $filter['_id']]);

                    $filter['ip_hits'] = 0;

                    if ($childs) {
                        $childs = count($childs);

                        if ($childs > 0) {
                            $filter['ip_hits'] = $childs;
                        }
                    }
                }
            }

            $this->addResponse('Ok', 0, ['filters' => $filters]);

            return true;
        } else if (count($filters) === 0) {
            $this->addResponse('No Filters!', 0, ['filters' => $filters]);

            return true;
        }

        $this->addResponse('Error retrieving filters', 1);

        return false;
    }

    public function getFilterById($id, $defaultStore = false)
    {
        if ($defaultStore) {
            $filter = $this->firewallFiltersDefaultStore->findById($id);
        } else {
            $filter = $this->firewallFiltersStore->findById($id);
        }

        if ($filter) {
            $this->addResponse('Ok', 0, ['filter' => $filter]);

            return $filter;
        }

        return false;
    }

    public function getFilterByAddress($address, $getChildren = false, $defaultStore = false)
    {
        if ($defaultStore) {
            $filter = $this->firewallFiltersDefaultStore->findBy(['address', '=', $address]);
            $getChildren = false;
        } else {
            $filter = $this->firewallFiltersStore->findBy(['address', '=', $address]);
        }

        if (isset($filter[0])) {
            if ($filter[0]['address_type'] !== 'host' &&
                $getChildren
            ) {
                $filters = $this->firewallFiltersStore->findBy(['parent_id', '=', $filter[0]['_id']]);

                if ($filters && count($filters) > 0) {
                    $filter[0]['ips'] = $filters;
                }
            }

            $this->addResponse('Ok', 0, ['filter' => $filter[0]]);

            return $filter[0];
        }

        $this->addResponse('No filter found for the given address ' . $address, 1);

        return false;
    }

    public function getFilterByAddressAndType($address, $type, $defaultStore = false)
    {
        if ($defaultStore) {
            $filter = $this->firewallFiltersDefaultStore->findBy([['address', '=', $address], ['address_type', '=', $type]]);
        } else {
            $filter = $this->firewallFiltersStore->findBy([['address', '=', $address], ['address_type', '=', $type]]);
        }

        if (isset($filter[0])) {
            $this->addResponse('Ok', 0, ['filter' => $filter[0]]);

            return $filter[0];
        }

        $this->addResponse('No filter found for the given address ' . $address, 1);

        return false;
    }

    public function getFilterByType($type, $defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewallFiltersDefaultStore->findBy(['address_type', '=', $type], ['filter_type' => 'desc']);
        } else {
            $filters = $this->firewallFiltersStore->findBy(['address_type', '=', $type], ['filter_type' => 'desc']);
        }

        if ($filters) {
            $this->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->addResponse('No filters found for the given type ' . $type, 1);

        return false;
    }

    public function getFilterByParentId($id)
    {
        $filters = $this->firewallFiltersStore->findBy(['parent_id', '=', $id]);

        if ($filters) {
            $this->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->addResponse('No filters found for the given parent ' . $id, 1);

        return false;
    }

    public function addFilter(array $data, $defaultStore = false)
    {
        if (!isset($data['filter_type']) ||
            (isset($data['filter_type']) &&
             ($data['filter_type'] !== 'allow' &&
              $data['filter_type'] !== 'block' &&
              $data['filter_type'] !== 'monitor')
            )
        ) {
            $this->addResponse('Please provide correct filter type', 1);

            return false;
        }

        if (!isset($data['address_type']) ||
            (isset($data['address_type']) &&
             ($data['address_type'] !== 'host' &&
              $data['address_type'] !== 'network' &&
              $data['address_type'] !== 'ip2location')
            )
        ) {
            $this->addResponse('Please provide correct address type', 1);

            return false;
        }

        if (!isset($data['address'])) {
            $this->addResponse('Please provide correct address', 1);

            return false;
        }

        if ($filterexists = $this->getFilterByAddress($data['address'])) {
            $this->addResponse('Filter with address ' . $data['address'] . ' already exists. Please see filter with ID: ' . $filterexists['_id'], 1);

            return false;
        }

        if (isset($data['address'])) {
            if ($data['address_type'] === 'host' || $data['address_type'] === 'network') {
                $address = explode('/', $data['address'])[0];

                if (!$this->validateIP($address)) {
                    $this->addResponse('Please provide correct address', 1);

                    return false;
                }
            } else if ($data['address_type'] === 'ip2location') {
                if ((!$this->config['ip2location_api_key'] ||
                     $this->config['ip2location_api_key'] === '') &&
                    (!$this->config['ip2location_io_api_key'] ||
                     $this->config['ip2location_io_api_key'] === '')
                ) {
                    $this->addResponse('Please set ip2location API key to add address type ip2location', 1);

                    return false;
                }
            }
        }

        if (!isset($data['updated_by'])) {
            $data['updated_by'] = 0;
        }
        if (!isset($data['updated_at'])) {
            $data['updated_at'] = time();
        }

        if (!isset($data['parent_id'])) {
            $data['parent_id'] = null;
        }

        if ($defaultStore) {
            return $this->firewallFiltersDefaultStore->insert($data);
        } else {
            return $this->firewallFiltersStore->insert($data);
        }
    }

    public function updateFilter(array $data)
    {
        if (!isset($data['id'])) {
            $this->addResponse('Please provide correct filter ID', 1);

            return false;
        }

        if (!$filter = $this->getFilterById($data['id'])) {
            $this->addResponse('Filter with ID ' . $data['id'] . ' does not exists', 1);

            return false;
        }

        if (!isset($data['filter_type'])) {
            $this->addResponse('Please provide correct filter type', 1);

            return false;
        }

        if (!isset($data['updated_by'])) {
            $filter['updated_by'] = 0;
        } else {
            $filter['updated_by'] = $data['updated_by'];
        }

        if (!isset($data['updated_at'])) {
            $filter['updated_at'] = time();
        } else {
            $filter['updated_at'] = $data['updated_at'];
        }

        $filter['filter_type'] = $data['filter_type'];

        return $this->firewallFiltersStore->update($filter);
    }

    public function removeFilter($id, $defaultStore = false)
    {
        if (!$filter = $this->getFilterById((int) $id, $defaultStore)) {
            $this->addResponse('Filter with ID ' . $id . ' does not exists', 1);

            return false;
        }

        if (!$defaultStore) {
            $childFilters = $this->getFilterByParentId((int) $filter['_id']);

            if ($childFilters && count($childFilters) > 0) {//Remove all childs
                $this->firewallFiltersStore->deleteBy(['parent_id', '=', (int) $filter['_id']]);
            }
        }

        if ($defaultStore) {
            return $this->firewallFiltersDefaultStore->deleteById((int) $filter['_id']);
        } else {
            return $this->firewallFiltersStore->deleteById((int) $filter['_id']);
        }
    }

    protected function validateIP($address)
    {
        $ipv6 = false;
        if (str_contains($address, ':')) {
            $ipv6 = true;
        }

        if (!$ipv6 && !$this->config['filter_ipv4']) {
            return false;
        }

        if ($ipv6 && !$this->config['filter_ipv6']) {
            return false;
        }

        if (!filter_var($address, FILTER_VALIDATE_IP, ($ipv6 ? FILTER_FLAG_IPV6 : NULL))) {
            $this->addResponse('Please enter correct ip address', 1);

            return false;
        }

        $allow_private_range = true;
        if (array_key_exists('allow_private_range', $this->config) &&
            !is_null($this->config['allow_private_range']) &&
            $this->config['allow_private_range'] === false
        ) {
            $allow_private_range = false;
        }
        if (!filter_var($address, FILTER_VALIDATE_IP, (!$allow_private_range ? FILTER_FLAG_NO_PRIV_RANGE : NULL))) {
            $this->addResponse('Please enter correct ip address, private range is not allowed.', 1);

            return false;
        }

        $allow_reserved_range = true;
        if (array_key_exists('allow_reserved_range', $this->config) &&
            !is_null($this->config['allow_reserved_range']) &&
            $this->config['allow_reserved_range'] === false
        ) {
            $allow_reserved_range = false;
        }
        if (!filter_var($address, FILTER_VALIDATE_IP, (!$allow_reserved_range ? FILTER_FLAG_NO_RES_RANGE : NULL))) {
            $this->addResponse('Please enter correct ip address, reserved range is not allowed.', 1);

            return false;
        }

        return true;
    }

    public function checkIp($ip, $removeFromAutoMonitoring = false)
    {
        if (!$this->validateIP($ip)) {
            return false;
        }

        $this->getConfig();

        if ($this->config['status'] === 'disable') {
            $this->addResponse('Firewall is disabled. Everything is allowed!', 2);

            return true;
        }

        //First Check - We check HOST entries
        $filter = $this->getFilterByAddressAndType($ip, 'host');

        if ($filter) {//We find the address in address_type host
            return $this->checkIPFilter($filter, $ip);
        }

        //Second Check - We check NETWORK entries
        $filters = $this->getFilterByType('network');
        if ($filters && count($filters) > 0) {
            foreach ($filters as $filterKey => $filter) {
                if (IpUtils::checkIp($ip, $filter['address'])) {
                    return $this->checkIPFilter($filter, $ip);
                }
            }
        }

        //Third Check - We check ip2location entries
        if (isset($this->config['ip2location_io_api_key']) &&
            $this->config['ip2location_io_api_key'] !== ''
        ) {
            $ip2locationFilters = [];

            $filters = $this->getFilterByType('ip2location');

            if ($filters && count($filters) > 0) {
                foreach ($filters as $filterKey => $filter) {
                    $ip2locationAddressArr = explode(':', $filter['address']);

                    if (count($ip2locationAddressArr) === 1) {
                        $ip2locationFilters[$ip2locationAddressArr[0]] = $filter['_id'];
                    } else if (count($ip2locationAddressArr) === 2) {
                        $ip2locationFilters[$ip2locationAddressArr[0]][$ip2locationAddressArr[1]] = $filter['_id'];
                    } else if (count($ip2locationAddressArr) === 3) {
                        $ip2locationFilters[$ip2locationAddressArr[0]][$ip2locationAddressArr[1]][$ip2locationAddressArr[2]] = $filter['_id'];
                    }
                }
            }

            if (count($ip2locationFilters) > 0) {
                $response = $this->getIpDetailsFromIp2locationAPI($ip);

                if ($response) {
                    $filterRule = null;

                    if (isset($ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])][strtolower($response['city_name'])])) {
                        $filterRule = $ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])][strtolower($response['city_name'])];
                    } else if (isset($ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])])) {
                        $filterRule = $ip2locationFilters[strtolower($response['country_code'])][strtolower($response['region_name'])];
                    } else if (isset($ip2locationFilters[strtolower($response['country_code'])])) {
                        $filterRule = $ip2locationFilters[strtolower($response['country_code'])];
                    }

                    if ($filterRule) {
                        $filter = $this->getFilterById($filterRule);

                        return $this->checkIPFilter($filter, $ip);
                    }
                }
            }
        }

        //We check HOST entries in default
        $filter = $this->getFilterByAddressAndType($ip, 'host', true);

        if ($filter) {//We find the address in address_type host
            return $this->checkIPFilter($filter);
        }

        //Forth - We check DEFAULT entries
        $this->config['default_filter_hit_count'] = (int) $this->config['default_filter_hit_count'] + 1;

        $this->updateConfig($this->config);

        //We check host entry in the default store
        $filter = $this->getFilterByAddressAndType($ip, 'host', true);

        if ($filter) {//We find the address in default store and bump its counter
            $this->bumpFilterHitCounter($filter, true);
        } else {//We add a new entry in default store
            $newFilter['address_type'] = 'host';
            $newFilter['address'] = $ip;
            $newFilter['hit_count'] = 1;
            $newFilter['updated_by'] = "000";
            $newFilter['updated_at'] = time();
            $newFilter['filter_type'] = $this->config['default_filter'];
            $this->addFilter($newFilter, true);
        }

        if ($this->config['default_filter'] === 'allow') {
            $this->addResponse('Allowed by default firewall filter', 0);

            return true;
        } else if ($this->config['default_filter'] === 'block') {
            $this->addResponse('Blocked by default firewall filter', 1);

            return false;
        }

        return true;
    }

    public function getIpDetailsFromIp2locationAPI($ip)
    {
        if (isset($this->config['ip2location_io_api_key']) &&
            $this->config['ip2location_io_api_key'] !== ''
        ) {
            try {
                $apiCallResponse = $this->remoteWebContent->get('https://api.ip2location.io/?key=' . $this->config['ip2location_io_api_key'] . '&ip=' . $ip);

                if ($apiCallResponse && $apiCallResponse->getStatusCode() === 200) {
                    $response = $apiCallResponse->getBody()->getContents();

                    $response = json_decode($response, true);

                    $this->addResponse('Details for IP: ' . $ip . ' retrieved successfully', 0, ['ip_details' => $response]);

                    return $response;
                } else {
                    throw new \Exception('Lookup failed because of code : ' . $apiCallResponse->getStatusCode());
                }

                return false;
            } catch (\throwable $e) {
                throw $e;
            }
        }

        return false;
    }

    protected function checkIPFilter($filter, $ip = false)
    {
        //Check if IP is in default store and remove it
        $inDefaultFilter = $this->getFilterByAddress($ip, false, true);
        if ($inDefaultFilter) {
            $this->removeFilter($inDefaultFilter['_id'], true);
        }

        if ($filter['address_type'] === 'host') {
            $ip = false;
        }

        if ($ip) {//Add a new Host Filter
            $parentFilter = $filter;

            $newFilter = $filter;
            $newFilter['address_type'] = 'host';
            $newFilter['address'] = $ip;
            $newFilter['hit_count'] = 0;
            $newFilter['parent_id'] = $newFilter['_id'];
            $newFilter['updated_at'] = time();
            unset($newFilter['_id']);

            $filter = $this->addFilter($newFilter);
        }

        if (isset($filter['parent_id'])) {
            $parentFilter = $this->getFilterById($filter['parent_id']);
        }

        $this->bumpFilterHitCounter($filter);

        if ($filter['filter_type'] === 'allow' ||
            $filter['filter_type'] === 'monitor'
        ) {
            $status = 'Allowed';
            $code = 0;

            if ($filter['filter_type'] === 'monitor') {
                //AutoUnblock - only host ip can be auto unblocked.
                if ((int) $this->config['auto_unblock_ip_minutes'] > 0) {
                    $blockedAt = Carbon::parse($filter['updated_at']);

                    if (time() > $blockedAt->addMinutes((int) $this->config['auto_unblock_ip_minutes'])->timestamp) {
                        $this->removeFromMonitoring($filter);
                    } else {
                        $status = 'Monitoring';
                        $code = 2;
                    }
                } else {
                    $status = 'Monitoring';
                    $code = 2;
                }
            }

            if (isset($parentFilter)) {
                $filter['parent_filter'] = $parentFilter;
            }

            $this->addResponse($status, $code, ['filter' => $filter]);

            return true;
        }

        if ($this->config['status'] === 'monitor') {
            if (isset($parentFilter)) {
                $filter['parent_filter'] = $parentFilter;
            }

            $this->addResponse('IP address is blocked, but firewall status is monitor so ip address is allowed!', 2, ['filter' => $filter]);

            return true;
        }

        if (isset($parentFilter)) {
            $filter['parent_filter'] = $parentFilter;
        }

        $this->addResponse('Blocked', 1, ['filter' => $filter]);

        return false;
    }

    public function removeFromMonitoring($filter)
    {
        $filter['filter_type'] = 'allow';

        $this->firewallFiltersStore->update($filter);
    }

    protected function bumpFilterHitCounter($filter, $defaultStore = false)
    {
        $filter['hit_count'] = (int) $filter['hit_count'] + 1;

        if ($defaultStore) {
            $this->firewallFiltersDefaultStore->update($filter);
        } else {
            $this->firewallFiltersStore->update($filter);
        }

        if (!$defaultStore && isset($filter['parent_id'])) {
            $filter = $this->getFilterById($filter['parent_id']);

            if ($filter) {
                $filter['hit_count'] = (int) $filter['hit_count'] + 1;

                $this->firewallFiltersStore->update($filter);
            }
        }
    }
}