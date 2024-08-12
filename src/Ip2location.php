<?php

namespace PHPFirewall;

use IP2LocationIO\Configuration;
use IP2LocationIO\IPGeolocation;
use IP2Location\Database;
use IP2Location\IpTools;
use League\Flysystem\FileAttributes;
use League\Flysystem\FilesystemException;
use League\Flysystem\UnableToListContents;
use League\Flysystem\UnableToMoveFile;
use League\Flysystem\UnableToReadFile;
use PHPFirewall\Firewall;
use SleekDB\Store;

class Ip2location
{
    public $ipTools;

    public $ipGeoLocation;

    public $dataPath;

    public $firewallFiltersIp2locationStore;

    protected $firewall;

    public function __construct(Firewall $firewall, $dataPath = null)
    {
        $this->firewall = $firewall;

        $this->ipTools = new IpTools;

        if (isset($this->firewall->config['ip2location_io_api_key']) &&
            $this->firewall->config['ip2location_io_api_key'] !== ''
        ) {
            $ip2locationIoConfiguration = new Configuration($this->firewall->config['ip2location_io_api_key']);

            $this->ipGeoLocation = new IPGeolocation($ip2locationIoConfiguration);
        }

        if ($dataPath) {
            $this->dataPath = $dataPath . '/ip2locationdata';
        } else {
            if (str_contains(__DIR__, '/vendor/')) {
                $this->dataPath = $this->firewall->dataPath . 'ip2locationdata';
            } else {
                $this->dataPath = fwbase_path($this->firewall->dataPath . 'ip2locationdata');
            }
        }

        $this->checkIp2locationPath();

        $this->initStores();
    }

    public function getIpDetailsFromIp2locationBIN($ip)
    {
        if (!$this->checkIPIsPublic($ip)) {
            return false;
        }

        try {
            $ip2locationBin =
                new \IP2Location\Database(
                    $this->dataPath . '/' . $this->firewall->config['ip2location_bin_file_code'] . '.BIN',
                    constant('\IP2Location\Database::' . $this->firewall->config['ip2location_bin_access_mode'])
                );
        } catch (\throwable $e) {
            //Log here
            if (str_contains($e->getMessage(), 'exist')) {
                $this->firewall->addResponse('Bin file does not exist, please download bin file first to check in bin file.', 1);
            } else {
                $this->firewall->addResponse($e->getMessage(), 1);
            }

            return false;
        }

        $ipDetailsArr = $ip2locationBin->lookup($ip, \IP2Location\Database::ALL);

        if ($ipDetailsArr) {
            $ipDetails['address'] = $ip;
            $ipDetails['country_code'] = $ipDetailsArr['countryCode'];
            $ipDetails['country_name'] = $ipDetailsArr['countryName'];
            $ipDetails['region_name'] = $ipDetailsArr['regionName'];
            $ipDetails['city_name'] = $ipDetailsArr['cityName'];
            $ipDetails['is_proxy'] = false;
            $ipDetails['proxy_type'] = '-';
            if ($ipProxyDetails = $this->getIpDetailsFromIp2locationProxyBIN($ip)) {
                $ipDetails = array_merge($ipDetails, $ipProxyDetails);
            }

            $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully using BIN file.', 0, ['ip_details' => $ipDetails]);

            return $ipDetails;
        }

        $this->firewall->addResponse('Details for IP: ' . $ip . ' not available in the BIN file. Please search API.', 2);

        return false;
    }

    public function getIpDetailsFromIp2locationProxyBIN($ip)
    {
        if (!$this->checkIPIsPublic($ip)) {
            return false;
        }

        try {
            $ip2locationProxyBin =
                new \IP2Proxy\Database(
                    $this->dataPath . '/' . $this->firewall->config['ip2location_proxy_bin_file_code'] . '.BIN',
                    constant('\IP2Proxy\Database::' . $this->firewall->config['ip2location_proxy_bin_access_mode'])
                );

            $ipDetailsArr = $ip2locationProxyBin->lookup($ip, \IP2Proxy\Database::ALL);
        } catch (\throwable $e) {
            //Log here
            if (str_contains($e->getMessage(), 'exist')) {
                $this->firewall->addResponse('Bin file does not exist, please download bin file first to check in bin file.', 1);
            } else {
                $this->firewall->addResponse($e->getMessage(), 1);
            }

            return false;
        }

        if ($ipDetailsArr && isset($ipDetailsArr['countryCode']) && $ipDetailsArr['countryCode'] !== '-') {
            $ipDetails['address'] = $ip;
            $ipDetails['is_proxy'] = $ipDetailsArr['isProxy'];
            $ipDetails['proxy_type'] = $ipDetailsArr['proxyType'];

            $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully using Proxy BIN file.', 0, ['ip_details' => $ipDetails]);

            return $ipDetails;
        }

        $this->firewall->addResponse('Details for IP: ' . $ip . ' not available in the Proxy BIN file. Please search API.', 2);

        return false;
    }

    public function getIpDetailsFromIp2locationAPI($ip)
    {
        if (!$this->checkIPIsPublic($ip)) {
            return false;
        }

        $index = $this->firewall->indexes->searchIndexes($ip, true);

        if ($index) {
            $firewallFiltersIp2locationStoreEntry = $this->firewallFiltersIp2locationStore->findById((int) $index);

            if ($firewallFiltersIp2locationStoreEntry) {
                $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully using indexes.', 0, ['ip_details' => $firewallFiltersIp2locationStoreEntry]);

                return $firewallFiltersIp2locationStoreEntry;
            }
        }

        $firewallFiltersIp2locationStoreEntry = $this->firewallFiltersIp2locationStore->findBy(['address', '=', $ip]);

        if ($firewallFiltersIp2locationStoreEntry && isset($firewallFiltersIp2locationStoreEntry[0])) {
            $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully using ip2location local database.', 0, ['ip_details' => $firewallFiltersIp2locationStoreEntry[0]]);

            $this->firewall->indexes->addToIndex($firewallFiltersIp2locationStoreEntry[0], false, true);//Add to index

            return $firewallFiltersIp2locationStoreEntry[0];
        }

        if ($this->ipGeoLocation) {
            try {
                $apiCallResponse = $this->ipGeoLocation->lookup($ip, $this->firewall->config['ip2location_io_api_language']);

                if ($apiCallResponse) {
                    $apiCallResponse = (array) $apiCallResponse;

                    $ipDetails['address'] = $apiCallResponse['ip'];
                    $ipDetails['country_code'] = $apiCallResponse['country_code'];
                    $ipDetails['region_name'] = $apiCallResponse['region_name'];
                    $ipDetails['city_name'] = $apiCallResponse['city_name'];
                    $ipDetails['is_proxy'] = $apiCallResponse['is_proxy'];
                    $ipDetails['proxy_type'] = '-';
                    if (isset($apiCallResponse['proxy']) && isset($apiCallResponse['proxy']['proxy_type'])) {
                        $ipDetails['proxy_type'] = $apiCallResponse['proxy']['proxy_type'];
                    }

                    $ipDetails = $this->firewallFiltersIp2locationStore->insert($ipDetails);

                    $this->firewall->indexes->addToIndex($ipDetails, false, true);//Add to index

                    $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully using API.', 0, ['ip_details' => $ipDetails]);

                    return $apiCallResponse;
                }
            } catch (\throwable $e) {
                //Log here
                $this->firewall->addResponse($e->getMessage(), 1);
            }
        } else {
            $this->firewall->addResponse('Lookup is using io API and io API keys are not set!', 1);
        }

        return false;
    }

    public function downloadBinFile()
    {
        $download = $this->downloadData(
                'https://www.ip2location.com/download/?token=' . $this->firewall->config['ip2location_api_key'] . '&file=' . $this->firewall->config['ip2location_bin_file_code'],
                $this->dataPath . '/' . $this->firewall->config['ip2location_bin_file_code'] . '.ZIP'
            );

        if ($download) {
            $this->processDownloadedBinFile($download);

            return true;
        }

        $this->firewall->addResponse('Error downloading file', 1);
    }

    public function downloadProxyBinFile()
    {
        $download = $this->downloadData(
                'https://www.ip2location.com/download/?token=' . $this->firewall->config['ip2location_api_key'] . '&file=' . $this->firewall->config['ip2location_proxy_bin_file_code'],
                $this->dataPath . '/' . $this->firewall->config['ip2location_proxy_bin_file_code'] . '.ZIP'
            );

        if ($download) {
            $this->processDownloadedBinFile($download, null, true);

            return true;
        }

        $this->firewall->addResponse('Error downloading file', 1);
    }

    public function processDownloadedBinFile($download, $trackCounter = null, $proxy = false)
    {
        if (!is_null($trackCounter)) {
            $this->trackCounter = $trackCounter;
        }

        if ($this->trackCounter === 0) {
            $this->firewall->addResponse('Error while downloading file: ' . $download->getBody()->getContents(), 1);

            return false;
        }

        //Extract here.
        $zip = new \ZipArchive;

        if ($proxy) {
            $file = $this->dataPath . '/' . $this->firewall->config['ip2location_proxy_bin_file_code'] . '.ZIP';
        } else {
            $file = $this->dataPath . '/' . $this->firewall->config['ip2location_bin_file_code'] . '.ZIP';
        }

        if ($zip->open($file) === true) {
            $zip->extractTo($this->dataPath . '/');

            $zip->close();
        }

        //Rename file to the bin file code name.
        try {
            $this->firewall->setLocalContent(false, $this->dataPath . '/');

            $folderContents = $this->firewall->localContent->listContents('');

            $renamedFile = false;

            foreach ($folderContents as $key => $content) {
                if ($content instanceof FileAttributes) {
                    if ($proxy &&
                        str_contains($content->path(), '.BIN') &&
                        str_contains($content->path(), 'PX3')
                    ) {
                        $binFile = $this->firewall->config['ip2location_proxy_bin_file_code'] . '.BIN';
                    } else if (!$proxy &&
                               str_contains($content->path(), '.BIN') &&
                               str_contains($content->path(), 'DB3')
                    ) {
                        $binFile = $this->firewall->config['ip2location_bin_file_code'] . '.BIN';
                    } else {
                        continue;
                    }

                    $this->firewall->localContent->move($content->path(), $binFile);

                    $renamedFile = true;

                    break;
                }
            }

            if (!$renamedFile){
                throw new \Exception('ip2locationdata has no files');
            }

            $this->firewall->setLocalContent();
        } catch (UnableToListContents | \throwable | UnableToMoveFile | FilesystemException $e) {
            throw $e;
        }

        if ($proxy) {
            $this->firewall->setConfigIp2locationProxyBinDownloadDate();

            try {
                $ip2locationProxyBin =
                    new \IP2Location\Database(
                        $this->dataPath . '/' . $this->firewall->config['ip2location_proxy_bin_file_code'] . '.BIN',
                        constant('\IP2Location\Database::' . $this->firewall->config['ip2location_proxy_bin_access_mode'])
                    );

                $this->firewall->setConfigIp2locationProxyBinVersion($ip2locationProxyBin->getDatabaseVersion());
            } catch (\throwable $e) {
                throw $e;
            }

            $this->firewall->addResponse('Updated ip2location bin file.');
        } else {
            $this->firewall->setConfigIp2locationBinDownloadDate();

            try {
                $ip2locationBin =
                    new \IP2Location\Database(
                        $this->dataPath . '/' . $this->firewall->config['ip2location_bin_file_code'] . '.BIN',
                        constant('\IP2Location\Database::' . $this->firewall->config['ip2location_bin_access_mode'])
                    );

                $this->firewall->setConfigIp2locationBinVersion($ip2locationBin->getDatabaseVersion());
            } catch (\throwable $e) {
                throw $e;
            }

            $this->firewall->addResponse('Updated ip2location bin file.');
        }

        return true;
    }

    protected function checkIPIsPublic($ip)
    {
        if ($this->firewall->validateIP($ip)) {
            $ipv6 = false;

            if (str_contains($ip, ':')) {
                $ipv6 = true;
            }

            $isPublic = filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                ($ipv6 ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4) | FILTER_FLAG_NO_PRIV_RANGE |  FILTER_FLAG_NO_RES_RANGE
            );

            if (!$isPublic) {
                $this->firewall->addResponse('IP Address : ' . $ip . ' is from a private range of IP addresses!', 2);

                return false;
            }
        } else {
            return false;
        }

        return true;
    }

    public function initStores()
    {
        $this->firewallFiltersIp2locationStore = new Store("firewall_filters_ip2location", $this->firewall->databaseDirectory, $this->firewall->storeConfiguration);
    }

    protected function checkIp2locationPath()
    {
        if (!is_dir($this->dataPath)) {
            if (!mkdir($this->dataPath, 0777, true)) {
                return false;
            }
        }
    }
}