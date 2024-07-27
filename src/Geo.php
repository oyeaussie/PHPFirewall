<?php

namespace PHPFirewall;

use League\Flysystem\FilesystemException;
use League\Flysystem\UnableToReadFile;
use PHPFirewall\Firewall;
use SleekDB\Store;

class Geo
{
    protected $firewall;

    protected $firewallGeoCountriesStore;

    protected $firewallGeoStatesStore;

    protected $firewallGeoCitiesStore;

    public function __construct(Firewall $firewall)
    {
        $this->firewall = $firewall;

        $this->checkGeoPath();

        $this->initStores();
    }

    public function geoGetCountries()
    {
        $countries = $this->firewallGeoCountriesStore->findAll();

        if ($countries) {
            $this->firewall->addResponse('OK', 0, ['countries' => $countries]);

            return $countries;
        }

        $this->firewall->addResponse('No countries found in database!', 1);

        return false;
    }

    public function geoGetStates($countryCode)
    {
        $states = $this->firewallGeoStatesStore->findBy(['country_code', '=', strtoupper($countryCode)]);

        if ($states) {
            $this->firewall->addResponse('OK', 0, ['states' => $states]);

            return $states;
        }

        $this->firewall->addResponse('No states found in database!', 1);

        return false;
    }

    public function geoGetCities($countryCode, $stateCode)
    {
        $cities = $this->firewallGeoCitiesStore->findBy([['country_code', '=', strtoupper($countryCode)], ['state_code', '=', strtoupper($stateCode)]]);

        if ($cities) {
            $this->firewall->addResponse('OK', 0, ['cities' => $cities]);

            return $cities;
        }

        $this->firewall->addResponse('No cities found in database!', 1);

        return false;
    }


    public function downloadGeodataFile()
    {
        $download = $this->firewall->downloadData(
                'https://raw.githubusercontent.com/dr5hn/countries-states-cities-database/master/countries%2Bstates%2Bcities.json',
                fwbase_path('firewalldata/geodata/countries+states+cities.json')
            );

        if ($download) {
            $this->processDownloadedGeodataFile($download);

            return true;
        }

        $this->firewall->addResponse('Error downloading file', 1);
    }

    public function processDownloadedGeodataFile($download, $trackCounter = null)
    {
        if (!is_null($trackCounter)) {
            $this->firewall->trackCounter = $trackCounter;
        }

        if ($this->firewall->trackCounter === 0) {
            $this->firewall->addResponse('Error while downloading file: ' . $download->getBody()->getContents(), 1);

            return false;
        }

        $this->firewallGeoCountriesStore->deleteStore();
        $this->firewallGeoStatesStore->deleteStore();
        $this->firewallGeoCitiesStore->deleteStore();
        // return true;
        $this->initStores();

        //Process Downloaded JSON File
        try {
            $this->firewall->setLocalContent(false, fwbase_path('firewalldata/geodata/'));

            $jsonFile = $this->firewall->localContent->read('countries+states+cities.json');

            $jsonFile = json_decode($jsonFile, true);

            $error = false;

            foreach ($jsonFile as $country) {
                $countryEntry = $this->firewallGeoCountriesStore->updateOrInsert(
                    [
                        'id'            => $country['id'],
                        'name'          => $country['name'],
                        'country_code'  => $country['iso2'],
                    ], false
                );

                if ($countryEntry) {
                    foreach ($country['states'] as $state) {
                        $stateEntry = $this->firewallGeoStatesStore->updateOrInsert(
                            [
                                'id'            => $state['id'],
                                'name'          => $state['name'],
                                'state_code'    => $state['state_code'],
                                'country_id'    => $country['id'],
                                'country_code'  => $country['iso2'],
                            ], false
                        );

                        if ($stateEntry) {
                            foreach ($state['cities'] as $city) {
                                $cityEntry = $this->firewallGeoCitiesStore->updateOrInsert(
                                    [
                                        'id'            => $city['id'],
                                        'name'          => $city['name'],
                                        'state_id'      => $state['id'],
                                        'state_code'    => $state['state_code'],
                                        'country_id'    => $country['id'],
                                        'country_code'  => $country['iso2']
                                    ], false
                                );

                                if (!$cityEntry) {
                                    $this->firewall->addResponse('Error adding city :' . $city['name'] . ' for state :' . $state['state_code'] . ' for country :' . $country['iso2']);

                                    $error = true;

                                    break 3;
                                }
                            }
                        } else {
                            $this->firewall->addResponse('Error adding state :' . $state['state_code'] . ' for country :' . $country['iso2']);

                            $error = true;

                            break 2;
                        }
                    }
                } else {
                    $this->firewall->addResponse('Error adding country :' . $country['iso2']);

                    $error = true;

                    break;
                }
            }

            $this->firewall->setLocalContent();
        } catch (UnableToReadFile | \throwable | FilesystemException $e) {
            throw $e;
        }

        if (!$error) {
            $this->firewall->setConfigGeodataDownloadDate();

            $this->firewall->addResponse('Updated Geodata database.');
        }

        return true;
    }

    protected function initStores()
    {
        $this->firewallGeoCountriesStore = new Store("firewall_geo_countries", $this->firewall->databaseDirectory, $this->firewall->storeConfiguration);

        $this->firewallGeoStatesStore = new Store("firewall_geo_states", $this->firewall->databaseDirectory, $this->firewall->storeConfiguration);

        $this->firewallGeoCitiesStore = new Store("firewall_geo_cities", $this->firewall->databaseDirectory, $this->firewall->storeConfiguration);
    }

    protected function checkGeoPath()
    {
        if (str_contains(__DIR__, '/vendor/')) {
            $dataPath = $this->firewall->dataPath . 'geodata';
        } else {
            $dataPath = fwbase_path($this->firewall->dataPath . 'geodata');
        }

        if (!is_dir($dataPath)) {
            if (!mkdir($dataPath, 0777, true)) {
                return false;
            }
        }
    }
}