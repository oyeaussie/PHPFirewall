<?php

class FirewallTest extends \Codeception\Test\Unit
{
    protected $firewall;

    protected function _before()
    {
        include __DIR__ . '/../vendor/autoload.php';

        $this->firewall = new \PHPFirewall\Firewall(false, __DIR__ . '/firewalldata');
    }

    protected function _after()
    {
    }

    public function testGetFirewallConfig()
    {
        $this->assertArrayHasKey('response', $this->firewall->getFirewallConfig());
        $this->assertArrayHasKey('responseCode', $this->firewall->getFirewallConfig()['response']);
        $response = $this->firewall->getFirewallConfig()['response'];
        $this->assertEquals($response['responseCode'], 0);
    }

    /**
     * @depends testGetFirewallConfig
     */
    public function testSetConfigStatus()
    {
        $this->firewall->setConfigStatus('monitor');
        $status = $this->firewall->getFirewallConfig()['response']['responseData']['status'];
        $this->assertEquals($status, 'monitor');

        $this->firewall->setConfigStatus('enable');
        $status = $this->firewall->getFirewallConfig()['response']['responseData']['status'];
        $this->assertEquals($status, 'enable');
    }

    /**
     * @depends testSetConfigStatus
     */
    public function testSetConfigFilter()
    {
        $this->firewall->setConfigFilter('v6', 'disable');
        $filterIpv6 = $this->firewall->getFirewallConfig()['response']['responseData']['filter_ipv6'];
        $this->assertEquals($filterIpv6, false);

        $this->firewall->setConfigFilter('v6', 'enable');
        $filterIpv6 = $this->firewall->getFirewallConfig()['response']['responseData']['filter_ipv6'];
        $this->assertEquals($filterIpv6, true);
    }

    /**
     * @depends testSetConfigFilter
     */
    public function testSetConfigRange()
    {
        $this->firewall->setConfigRange('private', 'disable');
        $filterRange = $this->firewall->getFirewallConfig()['response']['responseData']['allow_private_range'];
        $this->assertEquals($filterRange, false);

        $this->firewall->setConfigRange('private', 'enable');
        $filterRange = $this->firewall->getFirewallConfig()['response']['responseData']['allow_private_range'];
        $this->assertEquals($filterRange, true);
    }

    /**
     * @depends testSetConfigRange
     */
    public function testSetConfigDefaultFilter()
    {
        $this->firewall->setConfigDefaultFilter('block');
        $defaultFilter = $this->firewall->getFirewallConfig()['response']['responseData']['default_filter'];
        $this->assertEquals($defaultFilter, 'block');

        $this->firewall->setConfigDefaultFilter('allow');
        $defaultFilter = $this->firewall->getFirewallConfig()['response']['responseData']['default_filter'];
        $this->assertEquals($defaultFilter, 'allow');
    }

    /**
     * @depends testSetConfigDefaultFilter
     */
    public function testSetConfigAutoUnblockIpMinutes()
    {
        $this->firewall->setConfigAutoUnblockIpMinutes(10);
        $defaultFilter = $this->firewall->getFirewallConfig()['response']['responseData']['auto_unblock_ip_minutes'];
        $this->assertEquals($defaultFilter, 10);

        $this->firewall->setConfigAutoUnblockIpMinutes(0);
        $defaultFilter = $this->firewall->getFirewallConfig()['response']['responseData']['auto_unblock_ip_minutes'];
        $this->assertFalse($defaultFilter);
    }

    /**
     * @depends testSetConfigAutoUnblockIpMinutes
     */
    public function testSetAutoIndexing()
    {
        $this->firewall->setAutoIndexing('disable');
        $autoIndexing = $this->firewall->getFirewallConfig()['response']['responseData']['auto_indexing'];
        $this->assertFalse($autoIndexing);

        $this->firewall->setAutoIndexing('enable');
        $autoIndexing = $this->firewall->getFirewallConfig()['response']['responseData']['auto_indexing'];
        $this->assertTrue($autoIndexing);
    }

    /**
     * @depends testSetAutoIndexing
     */
    public function testSetConfigIp2locationIoKey()
    {
        $this->firewall->setConfigIp2locationIoKey('abc123');
        $ioKey = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_io_api_key'];
        $this->assertEquals($ioKey, 'abc123');

        $this->firewall->setConfigIp2locationIoKey('null');
        $ioKey = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_io_api_key'];
        $this->assertNull($ioKey);
    }

    /**
     * @depends testSetConfigIp2locationIoKey
     */
    public function testSetConfigIp2locationKey()
    {
        $this->firewall->setConfigIp2locationKey('abc123');
        $ioKey = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_api_key'];
        $this->assertEquals($ioKey, 'abc123');

        $this->firewall->setConfigIp2locationKey('null');
        $ioKey = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_api_key'];
        $this->assertNull($ioKey);
    }

    /**
     * @depends testSetConfigIp2locationKey
     */
    public function testSetIp2locationPrimaryLookupMethod()
    {
        $this->firewall->setIp2locationPrimaryLookupMethod('bin');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_primary_lookup_method'];
        $this->assertEquals($method, 'BIN');

        $this->firewall->setIp2locationPrimaryLookupMethod('api');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_primary_lookup_method'];
        $this->assertEquals($method, 'API');

        $method = $this->firewall->setIp2locationPrimaryLookupMethod('abc123');
        $this->assertFalse($method);
    }

    /**
     * @depends testSetIp2locationPrimaryLookupMethod
     */
    public function testSetIp2locationBinFileCode()
    {
        $this->firewall->setIp2locationBinFileCode('DB3BINIPV6');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_bin_file_code'];
        $this->assertEquals($method, 'DB3BINIPV6');

        $this->firewall->setIp2locationBinFileCode('DB3LITEBINIPV6');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_bin_file_code'];
        $this->assertEquals($method, 'DB3LITEBINIPV6');

        $method = $this->firewall->setIp2locationBinFileCode('abc123');
        $this->assertFalse($method);

        $this->firewall->setIp2locationBinFileCode('null');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_bin_file_code'];
        $this->assertNull($method);
    }

    /**
     * @depends testSetIp2locationBinFileCode
     */
    public function testSetIp2locationProxyBinFileCode()
    {
        $this->firewall->setIp2locationProxyBinFileCode('PX3LITEBIN');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_proxy_bin_file_code'];
        $this->assertEquals($method, 'PX3LITEBIN');

        $this->firewall->setIp2locationProxyBinFileCode('PX3BIN');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_proxy_bin_file_code'];
        $this->assertEquals($method, 'PX3BIN');

        $method = $this->firewall->setIp2locationProxyBinFileCode('abc123');
        $this->assertFalse($method);

        $this->firewall->setIp2locationProxyBinFileCode('null');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_proxy_bin_file_code'];
        $this->assertNull($method);
    }

    /**
     * @depends testSetIp2locationProxyBinFileCode
     */
    public function testSetIp2locationBinAccessMode()
    {
        $this->firewall->setIp2locationBinAccessMode('SHARED_MEMORY');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_bin_access_mode'];
        $this->assertEquals($method, 'SHARED_MEMORY');

        $this->firewall->setIp2locationBinAccessMode('MEMORY_CACHE');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_bin_access_mode'];
        $this->assertEquals($method, 'MEMORY_CACHE');

        $this->firewall->setIp2locationBinAccessMode('FILE_IO');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_bin_access_mode'];
        $this->assertEquals($method, 'FILE_IO');

        $method = $this->firewall->setIp2locationBinAccessMode('abc123');
        $this->assertFalse($method);
    }

    /**
     * @depends testSetIp2locationBinAccessMode
     */
    public function testSetIp2locationProxyBinAccessMode()
    {
        $this->firewall->setIp2locationProxyBinAccessMode('SHARED_MEMORY');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_proxy_bin_access_mode'];
        $this->assertEquals($method, 'SHARED_MEMORY');

        $this->firewall->setIp2locationProxyBinAccessMode('MEMORY_CACHE');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_proxy_bin_access_mode'];
        $this->assertEquals($method, 'MEMORY_CACHE');

        $this->firewall->setIp2locationProxyBinAccessMode('FILE_IO');
        $method = $this->firewall->getFirewallConfig()['response']['responseData']['ip2location_proxy_bin_access_mode'];
        $this->assertEquals($method, 'FILE_IO');

        $method = $this->firewall->setIp2locationProxyBinAccessMode('abc123');
        $this->assertFalse($method);
    }

    /**
     * @depends testSetIp2locationProxyBinAccessMode
     */
    public function testAddFilters()
    {
        $this->firewall->localContent->deleteDirectory('db/firewall_filters');
        $this->firewall->localContent->deleteDirectory('db/firewall_filters_default');
        $this->firewall->localContent->deleteDirectory('db/firewall_filters_ip2location');

        $this->firewall->initStores();

        $newFilter = $this->firewall->addFilter(
            [
                'filter_type'       => 'block',
                'address_type'      => 'host',
                'address'           => '8.8.8.9'
            ]
        );
        $this->assertIsArray($newFilter);
        $this->assertEquals($newFilter['address'], '8.8.8.9');

        $newFilter = $this->firewall->addFilter(
            [
                'filter_type'       => 'block',
                'address_type'      => 'host',
                'address'           => '8.8.8.9'
            ]
        );
        $this->assertFalse($newFilter);

        $newFilter = $this->firewall->addFilter(
            [
                'filter_type'       => 'block',
                'address_type'      => 'network',
                'address'           => '10.100.100.0/24'
            ]
        );
        $this->assertIsArray($newFilter);
        $this->assertEquals($newFilter['address'], '10.100.100.0/24');

        $this->firewall->setConfigIp2locationKey($this->getModule('\Helper\Phpfirewall')->getKeys()['key']);
        $this->firewall->setConfigIp2locationIoKey($this->getModule('\Helper\Phpfirewall')->getKeys()['io_key']);

        $newFilter = $this->firewall->addFilter(
            [
                'filter_type'       => 'allow',
                'address_type'      => 'ip2location',
                'address'           => 'au:victoria:melbourne'
            ]
        );
        $this->assertIsArray($newFilter);
        $this->assertEquals($newFilter['address'], 'au:victoria:melbourne');

        $newFilter = $this->firewall->addFilter(
            [
                'filter_type'       => 'allow',
                'address_type'      => 'ip2location',
                'address'           => 'au:new south wales',
                'ip2location_proxy' => 'block'
            ]
        );
        $this->assertIsArray($newFilter);
        $this->assertEquals($newFilter['address'], 'au:new south wales');
        $this->assertEquals($newFilter['ip2location_proxy'], 'block');

        $newFilter = $this->firewall->addFilter(
            [
                'filter_type'       => 'block',
                'address_type'      => 'ip2location',
                'address'           => 'au',
            ]
        );
        $this->assertIsArray($newFilter);
        $this->assertEquals($newFilter['address'], 'au');
    }

    /**
     * @depends testAddFilters
     */
    public function testTestFilters()
    {
        $check = $this->firewall->checkIp('8.8.8.9');
        $this->assertFalse($check);
        $this->assertStringContainsString('host database', $this->firewall->getProcessedMicroTimers());

        $check = $this->firewall->checkIp('8.8.8.9');
        $this->assertFalse($check);
        $this->assertStringContainsString('indexes', $this->firewall->getProcessedMicroTimers());

        $check = $this->firewall->checkIp('10.10.10.1');
        $this->assertTrue($check);
        $this->assertStringContainsString('default database', $this->firewall->getProcessedMicroTimers());
        $this->firewall->setConfigDefaultFilter('block');
        $check = $this->firewall->checkIp('10.10.10.1');
        $this->assertFalse($check);
        $this->assertStringContainsString('default database', $this->firewall->getProcessedMicroTimers());
        $check = $this->firewall->checkIp('10.10.10.1');
        $this->assertFalse($check);
        $this->assertStringContainsString('indexes', $this->firewall->getProcessedMicroTimers());

        $check = $this->firewall->checkIp('10.100.100.10');
        $this->assertFalse($check);
        $this->assertStringContainsString('network database', $this->firewall->getProcessedMicroTimers());
        $check = $this->firewall->checkIp('10.100.100.10');
        $this->assertFalse($check);
        $this->assertStringContainsString('indexes', $this->firewall->getProcessedMicroTimers());

        $check = $this->firewall->checkIp('144.48.38.173');
        $this->assertTrue($check);
        $this->assertStringContainsString('ip2locationAPI database', $this->firewall->getProcessedMicroTimers());
        $check = $this->firewall->checkIp('144.48.38.173');
        $this->assertTrue($check);
        $this->assertStringContainsString('indexes', $this->firewall->getProcessedMicroTimers());

        $check = $this->firewall->checkIp('86.48.8.224');
        $this->assertTrue($check);
        $this->assertStringContainsString('ip2locationAPI database', $this->firewall->getProcessedMicroTimers());
        $check = $this->firewall->checkIp('86.48.8.224');
        $this->assertTrue($check);
        $this->assertStringContainsString('indexes', $this->firewall->getProcessedMicroTimers());

        $check = $this->firewall->checkIp('43.255.45.131');
        $this->assertFalse($check);
        $this->assertStringContainsString('ip2locationAPI database', $this->firewall->getProcessedMicroTimers());
        $check = $this->firewall->checkIp('43.255.45.131');
        $this->assertFalse($check);
        $this->assertStringContainsString('indexes', $this->firewall->getProcessedMicroTimers());

        $check = $this->firewall->checkIp('116.90.72.78');
        $this->assertFalse($check);
        $this->assertStringContainsString('ip2locationAPI database', $this->firewall->getProcessedMicroTimers());
        $check = $this->firewall->checkIp('116.90.72.78');
        $this->assertFalse($check);
        $this->assertStringContainsString('indexes', $this->firewall->getProcessedMicroTimers());
    }
}