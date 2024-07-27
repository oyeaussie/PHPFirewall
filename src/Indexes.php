<?php

namespace PHPFirewall;

use League\Flysystem\FilesystemException;
use League\Flysystem\UnableToReadFile;
use PHPFirewall\Firewall;

class Indexes
{
    protected $firewall;

    public function __construct(Firewall $firewall)
    {
        $this->firewall = $firewall;

        $this->checkIndexesPath();
    }

    public function searchIndexes($ip)
    {
        $this->firewall->setLocalContent(false, fwbase_path('firewalldata/indexes/'));

        $ipv4Index = null;
        $ipv6Index = null;

        if ($this->firewall->ipTools->isIpv4($ip)) {
            $ipv4Index = $this->firewall->ipTools->ipv4ToDecimal($ip);
        } else if ($this->firewall->ipTools->isIpv6($ip)) {
            $ipv6Index = $this->firewall->ipTools->ipv6ToDecimal($ip);
        }

        if ($ipv4Index) {
            $ipv4IndexArr = str_split($ipv4Index, 3);

            $ipv4IndexPath = join('/', $ipv4IndexArr);

            try {
                $file = $this->firewall->localContent->read($ipv4IndexPath . '/' . $ipv4Index . '.txt');

                if ($file) {
                    $file = explode(':', $file);

                    if (isset($file[0]) && (int) $file[0] > 0) {
                        if (isset($file[1]) && $file[1] === 'd') {
                            return [$file[0], true];
                        }

                        $this->firewall->setLocalContent();

                        return [$file[0], false];
                    }
                }
            } catch (\throwable | UnableToReadFile | FilesystemException $e) {
                $this->firewall->addResponse($e->getMessage(), 1);
            }
        } else if ($ipv6Index) {
            $ipv6IndexArr = str_split($ipv6Index, 10);

            $ipv6IndexPath = join('/', $ipv6IndexArr);

            try {
                $file = $this->firewall->localContent->write($ipv6IndexPath . '/' . $ipv6Index . '.txt');

                if ($file) {
                    $file = explode(':', $file);

                    if (isset($file[0]) && (int) $file[0] > 0) {
                        if (isset($file[1]) && $file[1] === 'd') {
                            return [$file[0], true];
                        }

                        $this->firewall->setLocalContent();

                        return [$file[0], false];
                    }
                }
            } catch (\throwable | UnableToReadFile | FilesystemException $e) {
                $this->firewall->addResponse($e->getMessage(), 1);
            }
        }

        $this->firewall->setLocalContent();

        return false;
    }

    public function reindexFilters($deleteIndexes = false, $norebuild = false)
    {
        if ($deleteIndexes) {
            $this->deleteIndexes();

            if ($norebuild) {
                $this->firewall->addResponse('Deleted all host IP indexes');

                return true;
            }
        }

        $filters = $this->firewall->getFilterByAddressType('host');
        $this->indexFilters($filters);
        $filters = $this->firewall->getFilterByAddressType('host', true);
        $this->indexFilters($filters, true);

        $this->firewall->addResponse('Reindexed all host IP addresses');

        return true;
    }

    protected function indexFilters($filters, $defaultStore = false)
    {
        $this->firewall->setLocalContent(false, fwbase_path('firewalldata/indexes/'));

        if ($filters && count($filters) > 0) {
            foreach ($filters as $filter) {
                $ipv4Index = null;
                $ipv6Index = null;

                if ($this->firewall->ipTools->isIpv4($filter['address'])) {
                    $ipv4Index = $this->firewall->ipTools->ipv4ToDecimal($filter['address']);
                } else if ($this->firewall->ipTools->isIpv6($filter['address'])) {
                    $ipv6Index = $this->firewall->ipTools->ipv6ToDecimal($filter['address']);
                }

                if ($ipv4Index) {
                    $ipv4IndexArr = str_split($ipv4Index, 3);

                    $ipv4IndexPath = join('/', $ipv4IndexArr);

                    try {
                        $this->firewall->localContent->write($ipv4IndexPath . '/' . $ipv4Index . '.txt', ($defaultStore === true ? $filter['id'] . ':d' : $filter['id']));

                        $this->firewall->setLocalContent();

                        return true;
                    } catch (\throwable | UnableToWriteFile | FilesystemException $e) {
                        $this->firewall->addResponse($e->getMessage(), 1);
                    }
                } else if ($ipv6Index) {
                    $ipv6IndexArr = str_split($ipv6Index, 10);

                    $ipv6IndexPath = join('/', $ipv6IndexArr);

                    try {
                        $this->firewall->localContent->write($ipv6IndexPath . '/' . $ipv6Index . '.txt', ($defaultStore === true ? $filter['id'] . ':d' : $filter['id']));

                        $this->firewall->setLocalContent();

                        return true;
                    } catch (\throwable | UnableToWriteFile | FilesystemException $e) {
                        $this->firewall->addResponse($e->getMessage(), 1);
                    }
                }
            }
        }

        $this->firewall->setLocalContent();

        return false;
    }

    public function addToIndex($filter, $defaultStore = false)
    {
        if (!$this->firewall->config['auto_indexing']) {
            return true;
        }

        return $this->indexFilters([$filter], $defaultStore);
    }

    public function removeFromIndex($ip)
    {
        if (!$this->firewall->config['auto_indexing']) {
            return true;
        }

        $this->firewall->setLocalContent(false, fwbase_path('firewalldata/indexes/'));

        $ipv4Index = null;
        $ipv6Index = null;

        if ($this->firewall->ipTools->isIpv4($ip)) {
            $ipv4Index = $this->firewall->ipTools->ipv4ToDecimal($ip);
        } else if ($this->firewall->ipTools->isIpv6($ip)) {
            $ipv6Index = $this->firewall->ipTools->ipv6ToDecimal($ip);
        }

        if ($ipv4Index) {
            $ipv4IndexArr = str_split($ipv4Index, 3);

            $ipv4IndexPath = join('/', $ipv4IndexArr);

            try {
                $file = $this->firewall->localContent->fileExists($ipv4IndexPath . $ipv4Index . '.txt');

                if ($file) {
                    $this->firewall->localContent->delete($ipv4IndexPath . $ipv4Index . '.txt');

                    $this->firewall->setLocalContent();

                    return true;
                }
            } catch (\throwable | UnableToReadFile | FilesystemException $e) {
                $this->firewall->addResponse($e->getMessage(), 1);
            }
        } else if ($ipv6Index) {
            $ipv6IndexArr = str_split($ipv6Index, 10);

            $ipv6IndexPath = join('/', $ipv6IndexArr);

            try {
                $file = $this->firewall->localContent->fileExists($ipv6IndexPath . $ipv6Index . '.txt');

                if ($file) {
                    $this->firewall->localContent->delete($ipv6IndexPath . $ipv6Index . '.txt');

                    $this->firewall->setLocalContent();

                    return true;
                }
            } catch (\throwable | UnableToReadFile | FilesystemException $e) {
                $this->firewall->addResponse($e->getMessage(), 1);
            }
        }

        $this->firewall->setLocalContent();

        return false;
    }

    protected function deleteIndexes()
    {
        $this->firewall->setLocalContent(false, fwbase_path('firewalldata/'));

        try {
            $this->firewall->localContent->deleteDirectory('indexes/');

            $this->checkIndexesPath();

            $this->firewall->setLocalContent();

            return true;
        } catch (\throwable | UnableToDeleteDirectory | FilesystemException $e) {
            $this->firewall->addResponse($e->getMessage(), 1);
        }

        $this->firewall->setLocalContent();

        return false;
    }

    protected function checkIndexesPath()
    {
        if (!is_dir(fwbase_path($this->firewall->dataPath . 'indexes'))) {
            if (!mkdir(fwbase_path($this->firewall->dataPath . 'indexes'), 0777, true)) {
                return false;
            }
        }
    }
}