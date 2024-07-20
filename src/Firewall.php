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

        if (count($filters) > 0) {
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

    public function getFilterByAddress($address, $checkIp = false)
    {
        if ($checkIp) {
            if (!$this->checkIP($address)) {
                $this->addResponse('Please provide correct address', 1);

                return false;
            }
        }

        $filter = $this->firewallFiltersStore->findBy(['address', '=', $address]);

        if (isset($filter[0])) {
            $this->addResponse('Ok', 0, ['filter' => $filter[0]]);

            return $filter[0];
        }

        $this->addResponse('No filter found for the given address ' . $address, 1);

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
              $data['address_type'] !== 'region')
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

                if (!$this->checkIP($address)) {
                    $this->addResponse('Please provide correct address', 1);

                    return false;
                }
            } else if ($data['address_type'] === 'region') {
                if (!$this->config['ip2locationAPI'] ||
                    $this->config['ip2locationAPI'] === ''
                ) {
                    $this->addResponse('Please set ip2location API key to add region', 1);

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

        return $this->firewallFiltersStore->deleteById($filter['_id']);
    }

    protected function checkIP($address)
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

    public function resetFilters(array $data)
    {
        //
    }

    public function checkList()
    {

        return true;
    }

    public function bumpFilterHitCounter()
    {
        //
    }

    public function removeFromMonitoring()
    {
        //
    }
}