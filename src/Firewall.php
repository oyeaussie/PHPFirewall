<?php

namespace PHPFirewall;

use Carbon\Carbon;
use PHPFirewall\Base;
use PHPFirewall\Geo;
use PHPFirewall\Indexes;
use PHPFirewall\Ip2location;
use SleekDB\Cache;
use SleekDB\Classes\IoHelper;
use Symfony\Component\HttpFoundation\IpUtils;

class Firewall extends Base
{
    public $geo;

    public $indexes;

    public $ip2location;

    public $ip;

    public function __construct($createRoot = false, $dataPath = null)
    {
        parent::__construct($createRoot, $dataPath);

        $this->geo = new Geo($this, $dataPath);

        $this->indexes = new Indexes($this, $dataPath);

        $this->ip2location = new Ip2location($this, $dataPath);
    }

    public function getFiltersCount($defaultStore = false)
    {
        $cacheTokenArray = ["count" => true];

        if ($defaultStore) {
            if ($this->firewallFiltersDefaultStore->_getUseCache() === true) {
                $cache = new Cache($this->firewallFiltersDefaultStore->getStorePath(), $cacheTokenArray, null);
                $cache->delete();
                $count = $this->firewallFiltersDefaultStore->count();
                IoHelper::updateFileContent($this->firewallFiltersDefaultStore->getStorePath() . '_cnt.sdb', function() use ($count) {
                    return $count;
                });
            } else {
                $count = $this->firewallFiltersDefaultStore->count();
            }

            return $count;
        } else {
            if ($this->firewallFiltersStore->_getUseCache() === true) {
                $cache = new Cache($this->firewallFiltersStore->getStorePath(), $cacheTokenArray, null);
                $cache->delete();
                $count = $this->firewallFiltersStore->count();
                IoHelper::updateFileContent($this->firewallFiltersStore->getStorePath() . '_cnt.sdb', function() use ($count) {
                    return $count;
                });
            } else {
                $count = $this->firewallFiltersStore->count();
            }

            return $count;
        }
    }

    public function getFilters($defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewallFiltersDefaultStore->findAll();
        } else {
            $filters = [];

            $hosts = $this->getFilterByType('host');
            if ($hosts && count($hosts) > 0) {
                $filters = array_merge($filters, $hosts);
            }

            $networks = $this->getFilterByType('network');
            if ($networks && count($networks) > 0) {
                $filters = array_merge($filters, $networks ?? []);
            }

            $ip2locationArr = $this->getFilterByType('ip2location');

            if ($ip2locationArr && count($ip2locationArr) > 0) {
                $ip2locationSortArr = [];

                foreach ($ip2locationArr as $ip2location) {
                    $ip2locationAddressArr = explode(':', $ip2location['address']);
                    if (count($ip2locationAddressArr) === 3) {
                        if (!isset($ip2locationSortArr[0])) {
                            $ip2locationSortArr[0] = [];
                        }
                        array_push($ip2locationSortArr[0], $ip2location);
                    } else if (count($ip2locationAddressArr) === 2) {
                        if (!isset($ip2locationSortArr[1])) {
                            $ip2locationSortArr[1] = [];
                        }
                        array_push($ip2locationSortArr[1], $ip2location);
                    } else if (count($ip2locationAddressArr) === 1) {
                        if (!isset($ip2locationSortArr[2])) {
                            $ip2locationSortArr[2] = [];
                        }
                        array_push($ip2locationSortArr[2], $ip2location);
                    }
                }

                if (count($ip2locationSortArr) > 0) {
                    ksort($ip2locationSortArr);

                    foreach ($ip2locationSortArr as $ip2locationSortKey => $ip2locationSort) {
                        $filters = array_merge($filters, $ip2locationSortArr[$ip2locationSortKey]);
                    }
                }
            }
        }

        if (count($filters) > 0) {
            if (!$defaultStore) {
                foreach ($filters as &$filter) {
                    if ($filter['address_type'] === 'host') {
                        $filter['ip_hits'] = '-';
                        continue;
                    }

                    $childs = $this->firewallFiltersStore->findBy(['parent_id', '=', $filter['id']]);

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

    public function getFilterById($id, $getChildren = false, $defaultStore = false)
    {
        if ($defaultStore) {
            $filter = $this->firewallFiltersDefaultStore->findById($id);
        } else {
            $filter = $this->firewallFiltersStore->findById($id);
        }

        if ($filter) {
            if ($filter['address_type'] !== 'host' &&
                $getChildren
            ) {
                $filters = $this->firewallFiltersStore->findBy(['parent_id', '=', $filter['id']]);

                if ($filters && count($filters) > 0) {
                    $filter['ips'] = $filters;
                }
            }

            $this->addResponse('Ok', 0, ['default_filter' => $defaultStore, 'filter' => $filter]);

            return $filter;
        }

        $this->addResponse('No filter found for the given id ' . $id, 1);

        return false;
    }

    public function searchFilterByAddress($address, $defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewallFiltersDefaultStore->findBy(['address', 'like', '%' . $address . '%']);
        } else {
            $filters = $this->firewallFiltersStore->findBy(['address', 'like', '%' . $address . '%']);
        }

        if (count($filters) > 0) {
            if (!$defaultStore) {
                foreach ($filters as &$filter) {
                    if ($filter['address_type'] === 'host') {
                        $filter['ip_hits'] = '-';
                        continue;
                    }

                    $childs = $this->firewallFiltersStore->findBy(['parent_id', '=', $filter['id']]);

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

            return $filters;
        }

        $this->addResponse('No filter found for the given address ' . $address, 1);

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
                $filters = $this->firewallFiltersStore->findBy(['parent_id', '=', $filter[0]['id']]);

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

    public function getFilterByAddressTypeAndFilterType($addressType, $filterType, $defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewallFiltersDefaultStore->findBy([['address_type', '=', $addressType], ['filter_type', '=', $filterType]]);
        } else {
            $filters = $this->firewallFiltersStore->findBy([['address_type', '=', $addressType], ['filter_type', '=', $filterType]]);
        }

        if ($filters) {
            $this->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->addResponse('No filters found for the given address type and filter type', 1);

        return false;
    }

    public function getFilterByAddressType($addressType, $defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewallFiltersDefaultStore->findBy([['address_type', '=', $addressType]]);
        } else {
            $filters = $this->firewallFiltersStore->findBy([['address_type', '=', $addressType]]);
        }

        if ($filters) {
            $this->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->addResponse('No filters found for the given address type and filter type', 1);

        return false;
    }

    public function getFilterByType($type, $defaultStore = false, $children = false)
    {
        $searchConditions = [['address_type', '=', $type]];
        if (!$children) {
            array_push($searchConditions, ['parent_id', '=', null]);
        }

        if ($defaultStore) {
            $filters = $this->firewallFiltersDefaultStore->findBy($searchConditions, ['filter_type' => 'desc']);
        } else {
            $filters = $this->firewallFiltersStore->findBy($searchConditions, ['filter_type' => 'desc']);
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
        $data = $this->normalizeFilterData($data);

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
            $this->addResponse('Filter with address ' . $data['address'] . ' already exists. Please see filter with ID: ' . $filterexists['id'], 1);

            return false;
        }

        if (isset($data['address'])) {
            if ($data['address_type'] === 'host' || $data['address_type'] === 'network') {

                if ($data['address_type'] === 'network' &&
                    !str_contains($data['address'], '/')
                ) {
                    $this->addResponse('Please type correct network address. Format is CIDR - network address/network mask', 1);

                    return false;
                }

                if ($data['address_type'] === 'host' &&
                    str_contains($data['address'], '/')
                ) {
                    $this->addResponse('Please type correct host address.', 1);

                    return false;
                }

                if ($data['address_type'] === 'network') {
                    try {
                        if (str_contains($data['address'], ':')) {
                            $range = $this->ip2location->ipTools->cidrToIpv6($data['address']);
                        } else {
                            $range = $this->ip2location->ipTools->cidrToIpv4($data['address']);
                        }
                    } catch (\throwable $e) {
                        $this->addResponse('Please type correct network address. Format is CIDR - network address/network mask', 1);

                        return false;
                    }
                }

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

        if (!isset($data['ip2location_proxy']) ||
            (isset($data['ip2location_proxy']) &&
             ($data['ip2location_proxy'] !== 'allow' &&
              $data['ip2location_proxy'] !== 'block')
            )
        ) {
            if ($data['address_type'] === 'ip2location') {
                $data['ip2location_proxy'] = 'allow';//Default is to allow proxy connections
            } else {
                $data['ip2location_proxy'] = '-';//Default is to allow proxy connections
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

        if (!isset($data['hit_count'])) {
            $data['hit_count'] = 0;
        }

        if ($defaultStore) {
            $newFilter = $this->firewallFiltersDefaultStore->insert($data);

            if ($newFilter) {
                if ($newFilter['address_type'] === 'host') {
                    $this->indexes->addToIndex($newFilter, true);
                }
            }
        } else {
            if ($data['address_type'] === 'host') {
                $inDefaultFilter = $this->getFilterByAddress($data['address'], false, true);

                if ($inDefaultFilter) {
                    $this->removeFilter($inDefaultFilter['id'], true);
                }
            }

            $newFilter = $this->firewallFiltersStore->insert($data);

            if ($newFilter) {
                if ($newFilter['address_type'] === 'host') {
                    $this->indexes->addToIndex($newFilter);
                }
            }
        }

        if ($data['address_type'] !== 'host') {
            $this->indexes->reindexFilters(true, true);//We have to clear index for new network/ips to be indexed again.
        }

        $this->systemLogger->info('FILTER_ADD', $newFilter);

        return $newFilter;
    }

    protected function normalizeFilterData($data)
    {
        $filterFields =
            [
                'id', 'filter_type', 'address_type', 'address', 'ip_hits', 'hit_count', 'updated_by', 'updated_at', 'ip2location_proxy'
            ];

        array_walk($data, function($value, $index) use (&$data, $filterFields) {
            if (!in_array($index, $filterFields)) {
                unset($data[$index]);
            }
        });

        return $data;
    }

    public function updateFilter(array $data, $defaultStore = false)
    {
        $data = $this->normalizeFilterData($data);

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

        if ($filter['address_type'] === 'host') {
            $this->indexes->removeFromIndex($filter['address']);
        }

        $this->systemLogger->info('FILTER_UPDATE', $filter);

        if ($defaultStore) {
            return $this->firewallFiltersDefaultStore->update($filter);
        }

        return $this->firewallFiltersStore->update($filter);
    }

    public function removeFilter($id, $defaultStore = false)
    {
        if (!$filter = $this->getFilterById((int) $id, false, $defaultStore)) {
            $this->addResponse('Filter with ID ' . $id . ' does not exists', 1);

            return false;
        }

        if (!$defaultStore) {
            $childFilters = $this->getFilterByParentId((int) $filter['id']);

            if ($childFilters && count($childFilters) > 0) {//Remove all childs
                foreach ($childFilters as $childFilter) {
                    if ($childFilter['address_type'] === 'host') {
                        $this->indexes->removeFromIndex($childFilter['address']);
                    }
                }

                $this->firewallFiltersStore->deleteBy(['parent_id', '=', (int) $filter['id']]);
            }
        }

        if ($defaultStore) {
            $deleteFilter = $this->firewallFiltersDefaultStore->deleteById((int) $filter['id']);

            if ($deleteFilter) {
                if ($filter['address_type'] === 'host') {
                    $this->indexes->removeFromIndex($filter['address']);
                }
            }
        } else {
            $deleteFilter = $this->firewallFiltersStore->deleteById((int) $filter['id']);

            if ($deleteFilter) {
                if ($filter['address_type'] === 'host') {
                    $this->indexes->removeFromIndex($filter['address']);
                }
            }
        }

        $this->systemLogger->info('FILTER_DELETE', $filter);

        return $deleteFilter;
    }

    public function moveFilter($id)//Move filter from default store to main store
    {
        if (!$filter = $this->getFilterById((int) $id, false, true)) {
            $this->addResponse('Filter with ID ' . $id . ' does not exists in default data store.', 1);

            return false;
        }

        $oldFilterId = $filter['id'];

        unset($filter['id']);

        $newFilter = $this->addFilter($filter);

        if ($newFilter) {
            $this->addResponse('Filter moved to main store. New ID: ' . $newFilter['id']);

            return true;
        }

        $this->systemLogger->info('FILTER_MOVE', $newFilter);

        $this->addResponse('Error moving filter', 1);

        return false;
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

        if (!$allow_private_range) {
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)) {
                $this->addResponse('Please enter correct ip address, reserved range is not allowed.', 1);

                return false;
            }
        }

        return true;
    }

    public function checkIp($ip = null, array $overrideIp2locationLookupSequence = null)
    {
        if (!$ip) {
            $ip = $this->ip2location->ipTools->getVisitorIp();
        }

        if (!$this->validateIP($ip)) {
            return false;
        }

        $this->ip = $ip;

        $this->getConfig();

        if ($this->config['status'] === 'disable') {
            $this->addResponse('Firewall is disabled. Everything is allowed!', 2);

            return true;
        }

        //Zero Check - We check Ip in Index
        $this->setMicroTimer('indexesCheckIpFilter', true, true);

        $indexes = $this->indexes->searchIndexes($ip);

        if ($indexes && is_array($indexes) && count($indexes) === 2) {
            $filter = $this->getFilterById($indexes[0], false, $indexes[1]);

            if ($filter) {
                $indexesCheckIpFilter = $this->checkIPFilter($filter, false, $indexes[1]);

                $this->setMicroTimer('indexesCheckIpFilter', true);

                return $indexesCheckIpFilter;
            }
        }

        //First Check - We check HOST entries
        $this->setMicroTimer('hostCheckIpFilter', true, true);

        $filter = $this->getFilterByAddressAndType($ip, 'host');

        if ($filter) {//We find the address in address_type host
            $hostCheckIpFilter = $this->checkIPFilter($filter, $ip);

            $this->setMicroTimer('hostCheckIpFilter', true);

            return $hostCheckIpFilter;
        }

        //Second Check - We check NETWORK entries
        $this->setMicroTimer('networkCheckIpFilter', true, true);

        $filters = $this->getFilterByType('network');

        if ($filters && count($filters) > 0) {
            foreach ($filters as $filterKey => $filter) {
                if (IpUtils::checkIp($ip, $filter['address'])) {
                    $networkCheckIpFilter = $this->checkIPFilter($filter, $ip);

                    $this->setMicroTimer('networkCheckIpFilter', true);

                    return $networkCheckIpFilter;
                }
            }
        }

        //Third Check - We check ip2location as per the primary set first and then secondary if we did not find the entry
        $this->setMicroTimer('ip2locationCheckIpFilter', true, true);

        $ip2locationFilters = [];

        $filters = $this->getFilterByType('ip2location');

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
                        $filter = $this->getFilterById($filterRule);

                        if (isset($filter['ip2location_proxy']) && $filter['ip2location_proxy'] === 'block') {
                            if (isset($response['is_proxy']) && $response['is_proxy'] === true) {
                                $filter['filter_type'] = 'block';
                            }
                        }

                        $ip2locationCheckIpFilter = $this->checkIPFilter($filter, $ip);

                        $this->setMicroTimer('ip2location' . $ip2locationLookupOptionsMethod . 'CheckIpFilter', true);

                        return $ip2locationCheckIpFilter;
                    }
                }
            }
        }

        //Forth - We check DEFAULT entries
        $this->setMicroTimer('defaultCheckIpFilter', true, true);

        $this->config['default_filter_hit_count'] = (int) $this->config['default_filter_hit_count'] + 1;

        $this->updateConfig($this->config);

        //We check host entry in the default store
        $filter = $this->getFilterByAddressAndType($ip, 'host', true);

        if ($filter) {//We find the address in default store and bump its counter
            $this->bumpFilterHitCounter($filter, true);

            $this->indexes->addToIndex($filter, true);//Add to index
        } else {//We add a new entry in default store
            $newFilter['address_type'] = 'host';
            $newFilter['address'] = $ip;
            $newFilter['hit_count'] = 1;
            $newFilter['updated_by'] = "000";
            $newFilter['updated_at'] = time();
            $newFilter['filter_type'] = $this->config['default_filter'];
            $filter = $this->addFilter($newFilter, true);
        }

        $this->setMicroTimer('defaultCheckIpFilter', true);

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

    protected function checkIPFilter($filter, $ip = false, $defaultStore = false)
    {
        if ($ip) {//Check if IP is in default store and remove it
            $inDefaultFilter = $this->getFilterByAddress($ip, false, true);
            if ($inDefaultFilter) {
                $this->removeFilter($inDefaultFilter['id'], true);
            }

            if ($filter['address_type'] === 'host') {
                $this->indexes->addToIndex($filter, $defaultStore);//Add to index

                $ip = false;
            }
        }

        if ($ip) {//Add a new Host Filter
            $parentFilter = $filter;

            $newFilter = $filter;
            $newFilter['address_type'] = 'host';
            $newFilter['address'] = $ip;
            $newFilter['hit_count'] = 0;
            $newFilter['parent_id'] = $newFilter['id'];
            $newFilter['updated_at'] = time();
            unset($newFilter['id']);

            $filter = $this->addFilter($newFilter);
        }

        if (isset($filter['parent_id'])) {
            $parentFilter = $this->getFilterById($filter['parent_id']);
        }

        $this->bumpFilterHitCounter($filter, $defaultStore);

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

            if ($status === 'Allowed' && $this->config['log_filter_allowed'] === true) {
                $this->filterLogger->notice('ALLOWED', ['ip' => $this->ip, 'filters_store'=> 'main', 'filter_id' => $filter['id']]);
            }

            $this->addResponse($status, $code, ['default_filter' => $defaultStore, 'filter' => $filter]);

            return true;
        }

        if ($this->config['status'] === 'monitor') {
            if (isset($parentFilter)) {
                $filter['parent_filter'] = $parentFilter;
            }

            $this->addResponse('IP address is blocked, but firewall status is monitor so ip address is allowed!', 2, ['default_filter' => $defaultStore, 'filter' => $filter]);

            return true;
        }

        if (isset($parentFilter)) {
            $filter['parent_filter'] = $parentFilter;
        }

        $this->filterLogger->notice('BLOCKED', ['ip' => $this->ip, 'filters_store'=> 'main', 'filter_id' => $filter['id']]);

        $this->addResponse('Blocked', 1, ['default_filter' => $defaultStore, 'filter' => $filter]);

        return false;
    }

    public function removeFromMonitoring($filter)
    {
        $filter['filter_type'] = 'allow';

        $this->firewallFiltersStore->update($filter);
    }

    public function resetFiltersCache()
    {
        $cacheArr = [];

        $cache = new Cache($this->firewallFiltersDefaultStore->getStorePath(), $cacheArr, null);
        $cache->deleteAll();

        $cache = new Cache($this->firewallFiltersStore->getStorePath(), $cacheArr, null);
        $cache->deleteAll();


        $this->addResponse('Deleted all cache');
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