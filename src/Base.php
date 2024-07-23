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

    protected $firewallFiltersDefaultStore;

    protected $firewallFiltersIp2locationStore;

    protected $dataPath;

    protected $ip2locationPath;

    public function __construct($createRoot = false, $dataPath = null)
    {
        $this->dataPath = $dataPath;

        if (!$this->dataPath) {
            $this->dataPath = str_contains(__DIR__, '/vendor/') ? __DIR__ . '/../../../../firewalldata/' : 'firewalldata/';
        }

        $this->ip2locationPath = $this->dataPath . 'ip2location/';

        $this->checkFirewallPath();

        $this->response = new Response;

        $this->setLocalContent($createRoot);

        $this->remoteWebContent = new Client(
            [
                'debug'           => false,
                'http_errors'     => true,
                'timeout'         => 2,
                'verify'          => false
            ]
        );

        $this->databaseDirectory =  $this->dataPath ? $this->dataPath . '/db/' : __DIR__ . '/../firewalldata/db/';

        $this->storeConfiguration =
        [
            "auto_cache"        => true,
            "cache_lifetime"    => null,
            "timeout"           => false,
            "primary_key"       => "id",
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

        $this->firewallFiltersDefaultStore = new Store("firewall_filters_default", $this->databaseDirectory, $this->storeConfiguration);

        $this->firewallFiltersIp2locationStore = new Store("firewall_filters_ip2location", $this->databaseDirectory, $this->storeConfiguration);

        $this->getConfig();

        if (!$this->config) {
            $this->config = $this->firewallConfigStore->updateOrInsert(
                [
                    'id'                                => 1,
                    'status'                            => 'enable',//Enable/disable/monitor
                    'filter_ipv4'                       => true,
                    'filter_ipv6'                       => true,
                    'allow_private_range'               => true,
                    'allow_reserved_range'              => true,
                    'default_filter'                    => 'allow',
                    'default_filter_hit_count'          => 0,
                    'auto_unblock_ip_minutes'           => false,
                    'ip2location_primary_lookup_method' => 'api',//api/bin
                    'ip2location_api_key'               => null,
                    'ip2location_bin_file_code'         => 'DB3LITEBINIPV6',//IP-COUNTRY-REGION-CITY
                    'ip2location_bin_access_mode'       => 'FILE_IO',//SHARED_MEMORY, MEMORY_CACHE, FILE_IO
                    'ip2location_bin_download_date'     => null,
                    'ip2location_io_api_key'            => null,
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

    public function setIp2locationBinFileCode($fileCode)
    {
        if ($fileCode === '') {
            $this->addResponse('Please provide correct fileCode.', 1);

            return false;
        }

        if ($fileCode === 'null') {
            $fileCode = null;
        }

        return $this->updateConfig(['ip2location_bin_file_code' => $fileCode]);
    }

    public function setIp2locationBinAccessMode($accessMode)
    {
        if ($accessMode === '') {
            $this->addResponse('Please provide correct fileMode.', 1);

            return false;
        }

        if ($accessMode === 'null') {
            $accessMode = null;
        }

        return $this->updateConfig(['ip2location_bin_access_mode' => $accessMode]);
    }

    public function setConfigIp2locationIoKey($key)
    {
        if ($key === '') {
            $this->addResponse('Please provide correct key.', 1);

            return false;
        }

        if ($key === 'null') {
            $key = null;
        }

        return $this->updateConfig(['ip2location_io_api_key' => $key]);
    }

    public function setConfigIp2locationBinDownloadDate()
    {
        return $this->updateConfig(['ip2location_bin_download_date' => time()]);
    }

    public function updateConfig($config)
    {
        $this->config = array_replace($this->config = $this->getConfig(), $config);

        $this->firewallConfigStore->update($this->config);

        return $this->getConfig();
    }

    public function setLocalContent($createRoot = false)
    {
        $this->localContent = new Filesystem(
            new LocalFilesystemAdapter(
                $this->dataPath ?? __DIR__ . '/../',
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

    protected function checkFirewallPath()
    {
        if (!is_dir(fwbase_path($this->dataPath))) {
            if (!mkdir(fwbase_path($this->dataPath), 0777, true)) {
                return false;
            }
        }

        if (!is_dir(fwbase_path($this->dataPath . 'ip2locationdata'))) {
            if (!mkdir(fwbase_path($this->dataPath . 'ip2locationdata'), 0777, true)) {
                return false;
            }
        }

        return true;
    }
}