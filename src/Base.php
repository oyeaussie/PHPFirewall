<?php

namespace PHPFirewall;

use GuzzleHttp\Client;
use League\Flysystem\Filesystem;
use League\Flysystem\Local\LocalFilesystemAdapter;
use PHPFirewall\Response;
use SleekDB\Store;
use cli\progress\Bar;

abstract class Base
{
    public $response;

    public $remoteWebContent;

    public $localContent;

    public $databaseDirectory;

    public $storeConfiguration;

    public $config;

    protected $firewallConfigStore;

    protected $firewallFiltersStore;

    public function __construct($createRoot = false, $dataPath = null)
    {
        if (!$dataPath) {
            $dataPath = str_contains(__DIR__, '/vendor/') ? __DIR__ . '/../../../../firewalldata/' : 'firewalldata/';
        }

        $this->checkFirewallPath($dataPath);

        $this->response = new Response;

        $this->setLocalContent($createRoot, $dataPath);

        $this->remoteWebContent = new Client(
            [
                'debug'           => false,
                'http_errors'     => true,
                'timeout'         => 10,
                'verify'          => false
            ]
        );

        $this->databaseDirectory =  $dataPath ? $dataPath . '/db/' : __DIR__ . '/../firewalldata/db/';

        $this->storeConfiguration =
        [
            "auto_cache"        => true,
            "cache_lifetime"    => null,
            "timeout"           => false,
            "primary_key"       => "_id",
            "search"            =>
                [
                    "min_length"    => 2,
                    "mode"          => "or",
                    "score_key"     => "scoreKey",
                    "algorithm"     => \SleekDB\Query::SEARCH_ALGORITHM["hits"]
                ],
            "folder_permissions" => 0777
        ];

        $this->firewallConfigStore = new Store("firewall_config", $this->databaseDirectory, $this->storeConfiguration);

        $this->firewallFiltersStore = new Store("firewall_filters", $this->databaseDirectory, $this->storeConfiguration);

        $this->getConfig();

        if (!$this->config) {
            $this->config = $this->firewallConfigStore->updateOrInsert(
                [
                    '_id'                       => 1,
                    'status'                    => 'enable',//Enable/disable/monitor
                    'filter_ipv4'               => true,
                    'filter_ipv6'               => true,
                    'allow_private_range'       => true,
                    'allow_reserved_range'      => true,
                    'default_filter'            => 'allow',
                    'default_filter_hit_count'  => 0,
                    'auto_unblock_ip_minutes'   => false,
                    'ip2location_api_key'       => null
                ]
            );
        }
    }

    public function getConfig()
    {
        $this->config = $this->firewallConfigStore->findById(1);

        return $this->config;
    }

    public function setConfigStatus($status)
    {
        $status = strtolower($status);

        if ($status !== 'enable' &&
            $status !== 'disable' &&
            $status !== 'monitor'
        ) {
            $this->addResponse('Please provide correct status.', 1);

            return false;
        }

        return $this->updateConfig(['status' => $status]);
    }

    public function setConfigFilter($type, $status)
    {
        $type = strtolower($type);
        $status = strtolower($status);

        if ($type !== 'v4' &&
            $type !== 'v6'
        ) {
            $this->addResponse('Please provide correct type.', 1);

            return false;
        }

        if ($status !== 'enable' &&
            $status !== 'disable'
        ) {
            $this->addResponse('Please provide correct status.', 1);

            return false;
        }

        return $this->updateConfig(['filter_ip' . $type => ($status === 'enable' ? true : false)]);
    }

    public function setConfigRange($type, $status)
    {
        $type = strtolower($type);
        $status = strtolower($status);

        if ($type !== 'private' &&
            $type !== 'reserved'
        ) {
            $this->addResponse('Please provide correct range type.', 1);

            return false;
        }

        if ($status !== 'enable' &&
            $status !== 'disable'
        ) {
            $this->addResponse('Please provide correct status.', 1);

            return false;
        }

        return $this->updateConfig(['allow_' . $type . '_range' => ($status === 'enable' ? true : false)]);
    }

    public function setConfigDefaultFilter($state)
    {
        $state = strtolower($state);

        if ($state !== 'allow' &&
            $state !== 'block'
        ) {
            $this->addResponse('Please provide correct default state.', 1);

            return false;
        }

        return $this->updateConfig(['default_filter' => $state]);
    }

    public function resetConfigDefaultFilterHitCount()
    {
        return $this->updateConfig(['default_filter_hit_count' => 0]);
    }

    public function setConfigAutoUnblockIpMinutes($minutes)
    {
        if ((int) $minutes === 0) {
            $minutes = false;
        }

        return $this->updateConfig(['auto_unblock_ip_minutes' => $minutes]);
    }

    public function setConfigIp2locationKey($key)
    {
        if ($key === '') {
            $this->addResponse('Please provide correct key.', 1);

            return false;
        }

        if ($key === 'null') {
            $key = null;
        }

        return $this->updateConfig(['ip2location_api_key' => $key]);
    }

    public function updateConfig($config)
    {
        $this->config = array_replace($this->config = $this->getConfig(), $config);

        return $this->firewallConfigStore->update($this->config);
    }

    public function setLocalContent($createRoot = false, $dataPath = null)
    {
        $this->localContent = new Filesystem(
            new LocalFilesystemAdapter(
                $dataPath ?? __DIR__ . '/../',
                null,
                LOCK_EX,
                LocalFilesystemAdapter::SKIP_LINKS,
                null,
                $createRoot
            ),
            []
        );
    }

    public function addResponse($responseMessage, int $responseCode = 0, $responseData = null)
    {
        $this->response->responseMessage = $responseMessage;

        $this->response->responseCode = $responseCode;

        if ($responseData !== null && is_array($responseData)) {
            $this->response->responseData = $responseData;
        } else {
            $this->response->responseData = [];
        }
    }

    protected function checkFirewallPath($dataPath)
    {
        if (!is_dir(fwbase_path($dataPath))) {
            if (!mkdir(fwbase_path($dataPath), 0777, true)) {
                return false;
            }
        }

        return true;
    }
}