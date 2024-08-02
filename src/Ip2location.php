<?php

namespace PHPFirewall;

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

    public $dataPath;

    public $firewallFiltersIp2locationStore;

    protected $firewall;

    public function __construct(Firewall $firewall)
    {
        $this->ipTools = new IpTools;

        $this->firewall = $firewall;

        if (str_contains(__DIR__, '/vendor/')) {
            $this->dataPath = $this->firewall->dataPath . 'ip2locationdata';
        } else {
            $this->dataPath = fwbase_path($this->firewall->dataPath . 'ip2locationdata');
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
            //Log it to logger here.
            return false;
        }

        $ipDetailsArr = $ip2locationBin->lookup($ip, \IP2Location\Database::ALL);

        if ($ipDetailsArr) {
            $ipDetails['ip'] = $ip;
            $ipDetails['country_code'] = $ipDetailsArr['countryCode'];
            $ipDetails['country_name'] = $ipDetailsArr['countryName'];
            $ipDetails['region_name'] = $ipDetailsArr['regionName'];
            $ipDetails['city_name'] = $ipDetailsArr['cityName'];

            $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully using BIN file.', 0, ['ip_details' => $ipDetails]);

            return $ipDetails;
        }

        return false;
    }

    public function getIpDetailsFromIp2locationAPI($ip)
    {
        if (!$this->checkIPIsPublic($ip)) {
            return false;
        }

        $firewallFiltersIp2locationStoreEntry = $this->firewallFiltersIp2locationStore->findBy(['ip', '=', $ip]);

        if ($firewallFiltersIp2locationStoreEntry && isset($firewallFiltersIp2locationStoreEntry[0])) {
            $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully', 0, ['ip_details' => $firewallFiltersIp2locationStoreEntry[0]]);

            return $firewallFiltersIp2locationStoreEntry[0];
        }

        if (isset($this->firewall->config['ip2location_io_api_key']) &&
            $this->firewall->config['ip2location_io_api_key'] !== ''
        ) {
            try {
                $apiCallResponse = $this->firewall->remoteWebContent->get('https://api.ip2location.io/?key=' . $this->firewall->config['ip2location_io_api_key'] . '&ip=' . $ip);

                if ($apiCallResponse && $apiCallResponse->getStatusCode() === 200) {
                    $response = $apiCallResponse->getBody()->getContents();

                    $response = json_decode($response, true);

                    $ipDetails['ip'] = $response['ip'];
                    $ipDetails['country_code'] = $response['country_code'];
                    $ipDetails['region_name'] = $response['region_name'];
                    $ipDetails['city_name'] = $response['city_name'];

                    $ipDetails = $this->firewallFiltersIp2locationStore->insert($ipDetails);

                    $this->firewall->addResponse('Details for IP: ' . $ip . ' retrieved successfully using API.', 0, ['ip_details' => $ipDetails]);

                    return $response;
                } else {
                    throw new \Exception('Lookup failed because of code : ' . $apiCallResponse->getStatusCode());
                }
            } catch (\throwable $e) {
                //Log to logger here
                return false;
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
                    if (str_contains($content->path(), '.BIN')) {
                        if ($proxy) {
                            $file = $this->firewall->config['ip2location_proxy_bin_file_code'] . '.BIN';
                        } else {
                            $file = $this->firewall->config['ip2location_bin_file_code'] . '.BIN';
                        }

                        $this->firewall->localContent->move($content->path(), $file);

                        $renamedFile = true;

                        break;
                    }
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

    protected function initStores()
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