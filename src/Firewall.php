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

    public function getFilters()
    {
        $filters = $this->firewallFiltersStore->findBy(['parent_id', '=', null], ['filter_type' => 'desc']);

        if (count($filters) > 0) {
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

            $this->addResponse('Ok', 0, ['filters' => $filters]);

            return true;
        } else if (count($filters) === 0) {
            $this->addResponse('No Filters!', 0, ['filters' => $filters]);

            return true;
        }

        $this->addResponse('Error retrieving filters', 1);

        return false;
    }

    public function getFilterById($id)
    {
        $filter = $this->firewallFiltersStore->findById($id);

        if ($filter) {
            $this->addResponse('Ok', 0, ['filter' => $filter]);

            return $filter;
        }

        return false;
    }

    public function getFilterByAddress($address, $getChildren = false)
    {
        $filter = $this->firewallFiltersStore->findBy(['address', '=', $address]);

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

    public function getFilterByAddressAndType($address, $type)
    {
        $filter = $this->firewallFiltersStore->findBy([['address', '=', $address], ['address_type', '=', $type]]);

        if (isset($filter[0])) {
            $this->addResponse('Ok', 0, ['filter' => $filter[0]]);

            return $filter[0];
        }

        $this->addResponse('No filter found for the given address ' . $address, 1);

        return false;
    }

    public function getFilterByType($type)
    {
        $filters = $this->firewallFiltersStore->findBy(['address_type', '=', $type], ['filter_type' => 'desc']);

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

    public function addFilter(array $data)
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

        $data['parent_id'] = null;

        return $this->firewallFiltersStore->insert($data);
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

    public function removeFilter(array $data)
    {
        if (!isset($data['id'])) {
            $this->addResponse('Please provide correct filter ID', 1);

            return false;
        }

        if (!$filter = $this->getFilterById($data['id'])) {
            $this->addResponse('Filter with ID ' . $data['id'] . ' does not exists', 1);

            return false;
        }

        $childFilters = $this->getFilterByParentId($filter['_id']);

        if ($childFilters && count($childFilters) > 0) {//Remove all childs
            $this->firewallFiltersStore->deleteBy(['parent_id', '=', $filter['_id']]);
        }

        return $this->firewallFiltersStore->deleteById($filter['_id']);
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

        $filter = $this->getFilterByAddressAndType($ip, 'host');

        if ($filter) {//We find the address in address_type host
            return $this->checkIPFilter($filter);
        }

        $filters = $this->getFilterByType('network');

        if ($filters && count($filters) > 0) {
            foreach ($filters as $filter) {
                if ($filter['address_type'] === 'network') {
                    if (IpUtils::checkIp($ip, $filter['address'])) {
                        return $this->checkIPFilter($filter, $ip);
                    }
                } else if ($filter['address_type'] === 'ip2location') {
                    if (!$this->config['ip2location_io_api_key'] || $this->config['ip2location_io_api_key'] === '') {
                        continue;
                    } else {
                        // $checkOnApi =
                    }
                }
            }
        }

        $this->config['default_filter_hit_count'] = (int) $this->config['default_filter_hit_count'] + 1;

        $this->updateConfig($this->config);

        if ($this->config['default_filter'] === 'allow') {
            $this->addResponse('Allowed by default firewall filter', 0);

            return true;
        } else if ($this->config['default_filter'] === 'block') {
            $this->addResponse('Blocked by default firewall filter', 1);

            return false;
        }

        return true;
    }

    protected function checkIPFilter($filter, $ip = false)
    {
        if ($ip) {//Add a new Host Filter
            $parentFilter = $filter;

            $newFilter = $filter;
            $newFilter['address_type'] = 'host';
            $newFilter['address'] = $ip;
            $newFilter['hit_count'] = 0;
            $newFilter['parent_id'] = $newFilter['_id'];
            $newFilter['updated_at'] = time();
            unset($newFilter['_id']);

            $filter = $this->firewallFiltersStore->insert($newFilter);
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

    protected function bumpFilterHitCounter($filter = null)
    {
        $filter['hit_count'] = (int) $filter['hit_count'] + 1;

        $this->firewallFiltersStore->update($filter);

        if (isset($filter['parent_id'])) {
            $filter = $this->getFilterById($filter['parent_id']);

            if ($filter) {
                $filter['hit_count'] = (int) $filter['hit_count'] + 1;

                $this->firewallFiltersStore->update($filter);
            }
        }
    }
}