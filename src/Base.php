<?php

namespace PHPFirewall;

use Carbon\Carbon;
use GuzzleHttp\Client;
use League\Csv\Reader;
use League\Csv\Writer;
use League\Flysystem\Filesystem;
use League\Flysystem\FilesystemException;
use League\Flysystem\Local\LocalFilesystemAdapter;
use League\Flysystem\UnableToWriteFile;
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

    public $dataPath;

    public $trackCounter;

    public $trackTicksCounter;

    protected $firewallConfigStore;

    protected $firewallFiltersStore;

    protected $firewallFiltersDefaultStore;

    protected $firewallFiltersIp2locationStore;

    protected $ip2locationPath;

    protected $microtime = 0;

    protected $totalMicrotime = 0;

    protected $memoryusage = 0;

    protected $microTimers = [];

    public function __construct($createRoot = false, $dataPath = null)
    {
        $this->dataPath = $dataPath;

        if (!$this->dataPath) {
            $this->dataPath = str_contains(__DIR__, '/vendor/') ? __DIR__ . '/../../../../firewalldata/' : 'firewalldata/';
        }

        $this->ip2locationPath = $this->dataPath . 'ip2location/';

        $this->checkFirewallPath();

        $this->response = new Response;

        $this->setLocalContent($createRoot, $dataPath);

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
                    'auto_indexing'                     => true,//Index host addresses in main and default filters
                    'ip2location_api_key'               => null,
                    'ip2location_bin_file_code'         => 'DB3LITEBINIPV6',//IP-COUNTRY-REGION-CITY
                    'ip2location_bin_access_mode'       => 'FILE_IO',//SHARED_MEMORY, MEMORY_CACHE, FILE_IO
                    'ip2location_bin_download_date'     => null,
                    'ip2location_io_api_key'            => null,
                    'ip2location_primary_lookup_method' => 'API',//API/BIN
                    'geodata_download_date'             => null
                ]
            );
        }

        $this->getConfig();
    }

    public function getFirewallConfig()
    {
        $this->getConfig();

        unset($this->config['id']);

        $this->addResponse('Ok', 0, $this->config);

        return (array) $this->response;
    }

    protected function getConfig()
    {
        $this->config = $this->firewallConfigStore->findById(1);

        if ($this->config['ip2location_bin_download_date']) {
            $this->config['ip2location_bin_download_date'] = (Carbon::parse($this->config['ip2location_bin_download_date']))->toDateTimeString();
        }

        if ($this->config['geodata_download_date']) {
            $this->config['geodata_download_date'] = (Carbon::parse($this->config['geodata_download_date']))->toDateTimeString();
        }

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

    public function setAutoIndexing($status)
    {
        $status = strtolower($status);

        if ($status !== 'enable' &&
            $status !== 'disable'
        ) {
            $this->addResponse('Please provide correct status.', 1);

            return false;
        }

        return $this->updateConfig(['auto_indexing' => ($status === 'enable' ? true : false)]);
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
            $this->addResponse('Please provide correct file code.', 1);

            return false;
        }

        if ($fileCode === 'null') {
            $fileCode = null;
        }

        return $this->updateConfig(['ip2location_bin_file_code' => strtoupper($fileCode)]);
    }

    public function setIp2locationBinAccessMode($accessMode)
    {
        if ($accessMode === '') {
            $this->addResponse('Please provide correct file mode.', 1);

            return false;
        }

        if ($accessMode === 'null') {
            $accessMode = null;
        }

        return $this->updateConfig(['ip2location_bin_access_mode' => strtoupper($accessMode)]);
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

    public function setIp2locationPrimaryLookupMethod($lookupMethod)
    {
        if ($lookupMethod === '' ||
            ($lookupMethod !== 'API' && $lookupMethod !== 'BIN')
        ) {
            $this->addResponse('Please provide correct primary method.', 1);

            return false;
        }

        return $this->updateConfig(['ip2location_primary_lookup_method' => strtoupper($lookupMethod)]);
    }

    public function setConfigIp2locationBinDownloadDate()
    {
        return $this->updateConfig(['ip2location_bin_download_date' => time()]);
    }

    public function setConfigGeodataDownloadDate()
    {
        return $this->updateConfig(['geodata_download_date' => time()]);
    }

    public function updateConfig($config)
    {
        $this->config = array_replace($this->config = $this->getConfig(), $config);

        $this->firewallConfigStore->update($this->config);

        return $this->getConfig();
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

    public function getMicroTimer()
    {
        return $this->microTimers;
    }

    public function getTotalMicrotimer()
    {
        return (microtime(true) - $this->totalMicrotime);
    }

    public function downloadData($url, $sink)
    {
        $this->trackCounter = 0;
        $this->trackTicksCounter = 0;

        $download = $this->remoteWebContent->request(
            'GET',
            $url,
            [
                'progress' => function(
                    $downloadTotal,
                    $downloadedBytes,
                    $uploadTotal,
                    $uploadedBytes
                ) {
                    if ($downloadTotal === 0 || $downloadedBytes === 0) {
                        return;
                    }

                    //Trackcounter is needed as guzzelhttp runs this in a while loop causing too many updates with same download count.
                    //So this way, we only update progress when there is actually an update.
                    if ($downloadedBytes === $this->trackCounter) {
                        return;
                    }

                    $this->trackCounter = $downloadedBytes;

                    if (!$this->progress) {
                        $this->newProgress(100);
                    }

                    if ($downloadedBytes === $downloadTotal) {
                        if ($this->progress) {
                            $this->updateProgress('Downloading file ' . '... (' . $downloadTotal . '/' . $downloadTotal . ')');

                            $this->finishProgress();

                            $this->progress = null;
                        }
                    } else {
                        $downloadPercentTicks = (int) (($downloadedBytes * 100) / $downloadTotal);

                        if ($downloadPercentTicks > $this->trackTicksCounter) {
                            $this->trackTicksCounter = $downloadPercentTicks;

                            $this->updateProgress('Downloading file ' . '... (' . $downloadedBytes . '/' . $downloadTotal . ')');
                        }
                    }
                },
                'verify'            => false,
                'connect_timeout'   => 5,
                'timeout'           => 360,
                'sink'              => $sink
            ]
        );


        if ($download->getStatusCode() === 200) {
            $this->addResponse('Download file from URL: ' . $url);

            return $download;
        }

        $this->addResponse('Download resulted in : ' . $download->getStatusCode(), 1);

        return false;
    }

    public function exportFilters()
    {
        $csv = Writer::createFromString();

        $header = [
            "filter_store","filter_type","address_type","address","updated_by","updated_at","hit_count","parent_id","id"
        ];

        $csv->insertOne($header);

        $filters = $this->firewallFiltersStore->findAll();

        if ($filters && count($filters) > 0) {
            array_walk($filters, function(&$filter)  use ($header) {
                $filter['filter_store'] = 'main';
                $filter = array_replace(array_flip($header), $filter);
            });
        }

        $csv->insertAll($filters);

        $filters = $this->firewallFiltersDefaultStore->findAll();

        if ($filters && count($filters) > 0) {
            array_walk($filters, function(&$filter)  use ($header) {
                $filter['filter_store'] = 'default';
                $filter = array_replace(array_flip($header), $filter);
            });
        }

        $csv->insertAll($filters);

        $this->setLocalContent(false, fwbase_path('firewalldata/backup/'));

        try {
            $fileName = time() . '-backup.csv';
            $this->localContent->write($fileName, $csv->toString());

            $this->addResponse('Backup complete! CSV file available at location ' . fwbase_path('firewalldata/backup/') . $fileName);

            $this->setLocalContent();

            return true;
        } catch (\throwable | UnableToWriteFile | FilesystemException $e) {
            $this->addResponse($e->getMessage(), 1);
        }

        $this->setLocalContent();

        return false;
    }

    public function importFilters($fileName)
    {
        try {
            $csv = Reader::createFromPath(fwbase_path('firewalldata/backup/' . $fileName), 'r');

            $csv->setHeaderOffset(0);

            $header = $csv->getHeader();

            $records = $csv->getRecords();

            $totalCount = $csv->count();

            $insertCount = 0;
            $errorRecords = [];

            if ($csv->count() > 0) {
                foreach ($records as $recordIndex => $record) {
                    $insert = false;
                    if (isset($record['filter_store']) && $record['filter_store'] === 'main') {
                        $insert = $this->firewallFiltersStore->updateOrInsert($record, true);
                    } else if (isset($record['filter_store']) && $record['filter_store'] === 'default') {
                        $insert = $this->firewallFiltersDefaultStore->updateOrInsert($record, true);
                    } else {
                        $errorRecords[$recordIndex] = $record;
                    }

                    if ($insert) {
                        $insertCount++;
                    }
                }
            }

            if ($insertCount === $totalCount) {
                $this->addResponse('Successfully restored ' . $insertCount . '/' . $totalCount . ' filters into the database.', 0, []);
            } else if (count($errorRecords) > 0) {
                $this->addResponse('Restored ' . $insertCount . '/' . $totalCount . ' filters into the database. Please check your CSV file.', 2, ['errors_on_line' => $errorRecords]);
            } else {
                $this->addResponse('Restored ' . $insertCount . '/' . $totalCount . ' filters into the database. Please check your csv file.', 2, []);
            }

            return true;
        } catch (\throwable $e) {
            $this->addResponse($e->getMessage(), 1);
        }

        return false;
    }

    protected function checkFirewallPath()
    {
        if (str_contains(__DIR__, '/vendor/')) {
            $dataPath = $this->dataPath;
        } else {
            $dataPath = fwbase_path($this->dataPath);
        }

        if (!is_dir($dataPath)) {
            if (!mkdir($dataPath, 0777, true)) {
                return false;
            }
        }

        if (!is_dir($dataPath . 'backup')) {
            if (!mkdir($dataPath . 'backup', 0777, true)) {
                return false;
            }
        }

        if (!is_dir($dataPath . 'ip2locationdata')) {
            if (!mkdir($dataPath . 'ip2locationdata', 0777, true)) {
                return false;
            }
        }

        return true;
    }

    protected function setMicroTimer($reference, $calculateMemoryUsage = false)
    {
        $microtime['reference'] = $reference;

        $now = microtime(true);
        if ($this->microtime === 0) {
            $microtime['difference'] = 0;
            $this->microtime = microtime(true);
        } else {
            $microtime['difference'] = $now - $this->microtime;
            $this->microtime = $now;
        }

        if (count($this->microTimers) === 0) {
            $this->totalMicrotime = $now;
        }

        if ($calculateMemoryUsage) {
            if ($this->memoryusage === 0) {
                $microtime['memoryusage'] = 0;
                $this->memoryusage = memory_get_usage();
            } else {
                $currentMemoryUsage = memory_get_usage();
                $microtime['memoryusage'] = $this->getMemUsage($currentMemoryUsage - $this->memoryusage);
                $this->memoryusage = $currentMemoryUsage;
            }
        }

        array_push($this->microTimers, $microtime);
    }

    protected function getMemUsage($bytes)
    {
        $unit=array('b','kb','mb','gb','tb','pb');

        return @round($bytes/pow(1024,($i=floor(log($bytes,1024)))),2).' '.$unit[$i];
    }
}