<?php

namespace PHPFirewall;

use PHPFirewall\Firewall;

class Filters
{
    protected $firewall;

    public function __construct(Firewall $firewall)
    {
        $this->firewall = $firewall;
    }

    public function getFiltersCount($defaultStore = false)
    {
        $cacheTokenArray = ["count" => true];

        if ($defaultStore) {
            if ($this->firewall->firewallFiltersDefaultStore->_getUseCache() === true) {
                $cache = new Cache($this->firewall->firewallFiltersDefaultStore->getStorePath(), $cacheTokenArray, null);
                $cache->delete();
                $count = $this->firewall->firewallFiltersDefaultStore->count();
                IoHelper::updateFileContent($this->firewall->firewallFiltersDefaultStore->getStorePath() . '_cnt.sdb', function() use ($count) {
                    return $count;
                });
            } else {
                $count = $this->firewall->firewallFiltersDefaultStore->count();
            }

            return $count;
        } else {
            if ($this->firewall->firewallFiltersStore->_getUseCache() === true) {
                $cache = new Cache($this->firewall->firewallFiltersStore->getStorePath(), $cacheTokenArray, null);
                $cache->delete();
                $count = $this->firewall->firewallFiltersStore->count();
                IoHelper::updateFileContent($this->firewall->firewallFiltersStore->getStorePath() . '_cnt.sdb', function() use ($count) {
                    return $count;
                });
            } else {
                $count = $this->firewall->firewallFiltersStore->count();
            }

            return $count;
        }
    }

    public function getFilters($defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewall->firewallFiltersDefaultStore->findAll();
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

                    foreach (array_keys($ip2locationSortArr) as $ip2locationSortKey) {
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

                    $childs = $this->firewall->firewallFiltersStore->findBy(['parent_id', '=', $filter['id']]);

                    $filter['ip_hits'] = 0;

                    if ($childs) {
                        $childs = count($childs);

                        if ($childs > 0) {
                            $filter['ip_hits'] = $childs;
                        }
                    }
                }
            }

            $this->firewall->addResponse('Ok', 0, ['filters' => $filters]);

            return true;
        } else if (count($filters) === 0) {
            $this->firewall->addResponse('No Filters!', 0, ['filters' => $filters]);

            return true;
        }

        $this->firewall->addResponse('Error retrieving filters', 1);

        return false;
    }

    public function getFilterById($id, $getChildren = false, $defaultStore = false)
    {
        if ($defaultStore) {
            $filter = $this->firewall->firewallFiltersDefaultStore->findById($id);
        } else {
            $filter = $this->firewall->firewallFiltersStore->findById($id);
        }

        if ($filter) {
            if ($filter['address_type'] !== 'host' &&
                $getChildren
            ) {
                $filters = $this->firewall->firewallFiltersStore->findBy(['parent_id', '=', $filter['id']]);

                if ($filters && count($filters) > 0) {
                    $filter['ips'] = $filters;
                }
            }

            $this->firewall->addResponse('Ok', 0, ['default_filter' => $defaultStore, 'filter' => $filter]);

            return $filter;
        }

        $this->firewall->addResponse('No filter found for the given id ' . $id, 1);

        return false;
    }

    public function searchFilterByAddress($address, $defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewall->firewallFiltersDefaultStore->findBy(['address', 'like', '%' . $address . '%']);
        } else {
            $filters = $this->firewall->firewallFiltersStore->findBy(['address', 'like', '%' . $address . '%']);
        }

        if (count($filters) > 0) {
            if (!$defaultStore) {
                foreach ($filters as &$filter) {
                    if ($filter['address_type'] === 'host') {
                        $filter['ip_hits'] = '-';
                        continue;
                    }

                    $childs = $this->firewall->firewallFiltersStore->findBy(['parent_id', '=', $filter['id']]);

                    $filter['ip_hits'] = 0;

                    if ($childs) {
                        $childs = count($childs);

                        if ($childs > 0) {
                            $filter['ip_hits'] = $childs;
                        }
                    }
                }
            }

            $this->firewall->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->firewall->addResponse('No filter found for the given address ' . $address, 1);

        return false;
    }

    public function getFilterByAddress($address, $getChildren = false, $defaultStore = false)
    {
        if ($defaultStore) {
            $filter = $this->firewall->firewallFiltersDefaultStore->findBy(['address', '=', $address]);
            $getChildren = false;
        } else {
            $filter = $this->firewall->firewallFiltersStore->findBy(['address', '=', $address]);
        }

        if (isset($filter[0])) {
            if ($filter[0]['address_type'] !== 'host' &&
                $getChildren
            ) {
                $filters = $this->firewall->firewallFiltersStore->findBy(['parent_id', '=', $filter[0]['id']]);

                if ($filters && count($filters) > 0) {
                    $filter[0]['ips'] = $filters;
                }
            }

            $this->firewall->addResponse('Ok', 0, ['filter' => $filter[0]]);

            return $filter[0];
        }

        $this->firewall->addResponse('No filter found for the given address ' . $address, 1);

        return false;
    }

    public function getFilterByAddressAndType($address, $type, $defaultStore = false)
    {
        if ($defaultStore) {
            $filter = $this->firewall->firewallFiltersDefaultStore->findBy([['address', '=', $address], ['address_type', '=', $type]]);
        } else {
            $filter = $this->firewall->firewallFiltersStore->findBy([['address', '=', $address], ['address_type', '=', $type]]);
        }

        if (isset($filter[0])) {
            $this->firewall->addResponse('Ok', 0, ['filter' => $filter[0]]);

            return $filter[0];
        }

        $this->firewall->addResponse('No filter found for the given address ' . $address, 1);

        return false;
    }

    public function getFilterByAddressTypeAndFilterType($addressType, $filterType, $defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewall->firewallFiltersDefaultStore->findBy([['address_type', '=', $addressType], ['filter_type', '=', $filterType]]);
        } else {
            $filters = $this->firewall->firewallFiltersStore->findBy([['address_type', '=', $addressType], ['filter_type', '=', $filterType]]);
        }

        if ($filters) {
            $this->firewall->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->firewall->addResponse('No filters found for the given address type and filter type', 1);

        return false;
    }

    public function getFilterByAddressType($addressType, $defaultStore = false)
    {
        if ($defaultStore) {
            $filters = $this->firewall->firewallFiltersDefaultStore->findBy([['address_type', '=', $addressType]]);
        } else {
            $filters = $this->firewall->firewallFiltersStore->findBy([['address_type', '=', $addressType]]);
        }

        if ($filters) {
            $this->firewall->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->firewall->addResponse('No filters found for the given address type and filter type', 1);

        return false;
    }

    public function getFilterByType($type, $defaultStore = false, $children = false)
    {
        $searchConditions = [['address_type', '=', $type]];
        if (!$children) {
            array_push($searchConditions, ['parent_id', '=', null]);
        }

        if ($defaultStore) {
            $filters = $this->firewall->firewallFiltersDefaultStore->findBy($searchConditions, ['filter_type' => 'desc']);
        } else {
            $filters = $this->firewall->firewallFiltersStore->findBy($searchConditions, ['filter_type' => 'desc']);
        }

        if ($filters) {
            $this->firewall->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->firewall->addResponse('No filters found for the given type ' . $type, 1);

        return false;
    }

    public function getFilterByParentId($id)
    {
        $filters = $this->firewall->firewallFiltersStore->findBy(['parent_id', '=', $id]);

        if ($filters) {
            $this->firewall->addResponse('Ok', 0, ['filters' => $filters]);

            return $filters;
        }

        $this->firewall->addResponse('No filters found for the given parent ' . $id, 1);

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
            $this->firewall->addResponse('Please provide correct filter type', 1);

            return false;
        }

        if (!isset($data['address_type']) ||
            (isset($data['address_type']) &&
             ($data['address_type'] !== 'host' &&
              $data['address_type'] !== 'network' &&
              $data['address_type'] !== 'ip2location')
            )
        ) {
            $this->firewall->addResponse('Please provide correct address type', 1);

            return false;
        }

        if (!isset($data['address'])) {
            $this->firewall->addResponse('Please provide correct address', 1);

            return false;
        }

        if ($filterexists = $this->getFilterByAddress($data['address'])) {
            $this->firewall->addResponse('Filter with address ' . $data['address'] . ' already exists. Please see filter with ID: ' . $filterexists['id'], 1);

            return false;
        }

        if (isset($data['address'])) {
            if ($data['address_type'] === 'host' || $data['address_type'] === 'network') {
                if ($data['address_type'] === 'network' &&
                    !str_contains($data['address'], '/')
                ) {
                    $this->firewall->addResponse('Please type correct network address. Format is CIDR - network address/network mask', 1);

                    return false;
                }

                if ($data['address_type'] === 'host' &&
                    str_contains($data['address'], '/')
                ) {
                    $this->firewall->addResponse('Please type correct host address.', 1);

                    return false;
                }

                if ($data['address_type'] === 'network') {
                    if (str_contains($data['address'], ':')) {
                        $range = $this->firewall->ip2location->ipTools->cidrToIpv6($data['address']);
                    } else {
                        $range = $this->firewall->ip2location->ipTools->cidrToIpv4($data['address']);
                    }

                    if (!isset($range['ip_start']) && !isset($range['ip_end'])) {
                        $this->firewall->addResponse('Please type correct network address. Format is CIDR - network address/network mask', 1);

                        return false;
                    }
                }

                $address = explode('/', $data['address'])[0];

                if (!$this->firewall->validateIP($address)) {
                    $this->firewall->addResponse('Please provide correct address', 1);

                    return false;
                }
            } else if ($data['address_type'] === 'ip2location') {
                if ((!$this->firewall->config['ip2location_api_key'] ||
                     $this->firewall->config['ip2location_api_key'] === '') &&
                    (!$this->firewall->config['ip2location_io_api_key'] ||
                     $this->firewall->config['ip2location_io_api_key'] === '')
                ) {
                    $this->firewall->addResponse('Please set ip2location API key to add address type ip2location', 1);

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
            $newFilter = $this->firewall->firewallFiltersDefaultStore->insert($data);

            if ($newFilter) {
                if ($newFilter['address_type'] === 'host') {
                    $this->firewall->indexes->addToIndex($newFilter, true);
                }
            }
        } else {
            if ($data['address_type'] === 'host') {
                $inDefaultFilter = $this->getFilterByAddress($data['address'], false, true);

                if ($inDefaultFilter) {
                    $this->removeFilter($inDefaultFilter['id'], true);
                }
            }

            $newFilter = $this->firewall->firewallFiltersStore->insert($data);

            if ($newFilter) {
                if ($newFilter['address_type'] === 'host') {
                    $this->firewall->indexes->addToIndex($newFilter);
                }
            }
        }

        if ($data['address_type'] !== 'host') {
            $this->firewall->indexes->reindexFilters(true, true);//We have to clear index for new network/ips to be indexed again.
        }

        $this->firewall->systemLogger->info('FILTER_ADD', $newFilter);

        return $newFilter;
    }

    public function updateFilter(array $data, $defaultStore = false)
    {
        $data = $this->normalizeFilterData($data);

        if (!isset($data['id'])) {
            $this->firewall->addResponse('Please provide correct filter ID', 1);

            return false;
        }

        if (!$filter = $this->getFilterById($data['id'])) {
            $this->firewall->addResponse('Filter with ID ' . $data['id'] . ' does not exists', 1);

            return false;
        }

        if (!isset($data['filter_type'])) {
            $this->firewall->addResponse('Please provide correct filter type', 1);

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
            $this->firewall->indexes->removeFromIndex($filter['address']);
        }

        $this->firewall->systemLogger->info('FILTER_UPDATE', $filter);

        if ($defaultStore) {
            return $this->firewall->firewallFiltersDefaultStore->update($filter);
        }

        return $this->firewall->firewallFiltersStore->update($filter);
    }

    public function removeFilter($id, $defaultStore = false)
    {
        if (!$filter = $this->getFilterById((int) $id, false, $defaultStore)) {
            $this->firewall->addResponse('Filter with ID ' . $id . ' does not exists', 1);

            return false;
        }

        if (!$defaultStore) {
            $childFilters = $this->getFilterByParentId((int) $filter['id']);

            if ($childFilters && count($childFilters) > 0) {//Remove all childs
                foreach ($childFilters as $childFilter) {
                    if ($childFilter['address_type'] === 'host') {
                        $this->firewall->indexes->removeFromIndex($childFilter['address']);
                    }
                }

                $this->firewall->firewallFiltersStore->deleteBy(['parent_id', '=', (int) $filter['id']]);
            }
        }

        if ($defaultStore) {
            $deleteFilter = $this->firewall->firewallFiltersDefaultStore->deleteById((int) $filter['id']);

            if ($deleteFilter) {
                if ($filter['address_type'] === 'host') {
                    $this->firewall->indexes->removeFromIndex($filter['address']);
                }
            }
        } else {
            $deleteFilter = $this->firewall->firewallFiltersStore->deleteById((int) $filter['id']);

            if ($deleteFilter) {
                if ($filter['address_type'] === 'host') {
                    $this->firewall->indexes->removeFromIndex($filter['address']);
                }
            }
        }

        $this->firewall->systemLogger->info('FILTER_DELETE', $filter);

        return $deleteFilter;
    }

    public function moveFilter($id)//Move filter from default store to main store
    {
        if (!$filter = $this->getFilterById((int) $id, false, true)) {
            $this->firewall->addResponse('Filter with ID ' . $id . ' does not exists in default data store.', 1);

            return false;
        }

        unset($filter['id']);

        $newFilter = $this->addFilter($filter);

        if ($newFilter) {
            $this->firewall->addResponse('Filter moved to main store. New ID: ' . $newFilter['id']);

            return true;
        }

        $this->firewall->systemLogger->info('FILTER_MOVE', $newFilter);

        $this->firewall->addResponse('Error moving filter', 1);

        return false;
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

    public function checkIPFilter($filter, $ip = false, $defaultStore = false)
    {
        if ($ip) {//Check if IP is in default store and remove it
            $inDefaultFilter = $this->getFilterByAddress($ip, false, true);
            if ($inDefaultFilter) {
                $this->removeFilter($inDefaultFilter['id'], true);
            }

            if ($filter['address_type'] === 'host') {
                $this->firewall->indexes->addToIndex($filter, $defaultStore);//Add to index

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
                if ((int) $this->firewall->config['auto_unblock_ip_minutes'] > 0) {
                    $blockedAt = Carbon::parse($filter['updated_at']);

                    if (time() > $blockedAt->addMinutes((int) $this->firewall->config['auto_unblock_ip_minutes'])->timestamp) {
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

            if ($status === 'Allowed' && $this->firewall->config['log_filter_allowed'] === true) {
                $this->firewall->filterLogger->notice('ALLOWED', ['ip' => $this->firewall->ip, 'filters_store'=> 'main', 'filter_id' => $filter['id']]);
            }

            $this->firewall->addResponse($status, $code, ['default_filter' => $defaultStore, 'filter' => $filter]);

            return true;
        }

        if ($this->firewall->config['status'] === 'monitor') {
            if (isset($parentFilter)) {
                $filter['parent_filter'] = $parentFilter;
            }

            $this->firewall->addResponse('IP address is blocked, but firewall status is monitor so ip address is allowed!', 2, ['default_filter' => $defaultStore, 'filter' => $filter]);

            return true;
        }

        if (isset($parentFilter)) {
            $filter['parent_filter'] = $parentFilter;
        }

        $this->firewall->filterLogger->notice('BLOCKED', ['ip' => $this->firewall->ip, 'filters_store'=> 'main', 'filter_id' => $filter['id']]);

        $this->firewall->addResponse('Blocked', 1, ['default_filter' => $defaultStore, 'filter' => $filter]);

        return false;
    }

    public function removeFromMonitoring($filter)
    {
        $filter['filter_type'] = 'allow';

        $this->firewall->firewallFiltersStore->update($filter);
    }

    public function resetFiltersCache()
    {
        $cacheArr = [];

        $cache = new Cache($this->firewall->firewallFiltersDefaultStore->getStorePath(), $cacheArr, null);
        $cache->deleteAll();

        $cache = new Cache($this->firewall->firewallFiltersStore->getStorePath(), $cacheArr, null);
        $cache->deleteAll();


        $this->firewall->addResponse('Deleted all cache');
    }

    public function bumpFilterHitCounter($filter, $defaultStore = false)
    {
        $filter['hit_count'] = (int) $filter['hit_count'] + 1;

        if ($defaultStore) {
            $this->firewall->firewallFiltersDefaultStore->update($filter);
        } else {
            $this->firewall->firewallFiltersStore->update($filter);
        }

        if (!$defaultStore && isset($filter['parent_id'])) {
            $filter = $this->getFilterById($filter['parent_id']);

            if ($filter) {
                $filter['hit_count'] = (int) $filter['hit_count'] + 1;

                $this->firewall->firewallFiltersStore->update($filter);
            }
        }
    }
}