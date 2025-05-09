<?php

namespace PHPFirewall;

class Profiling
{
    protected $microtime = 0;

    protected $totalMicrotime = 0;

    protected $memoryusage = 0;

    protected $microTimers = [];

    protected $firewall;

    public function __construct(Firewall $firewall)
    {
        $this->firewall = $firewall;
    }

    public function getMicroTimer()
    {
        return $this->microTimers;
    }

    public function getTotalMicrotimer()
    {
        return (microtime(true) - $this->totalMicrotime);
    }

    public function getProcessedMicroTimers()
    {
        $microtimers = $this->getMicroTimer();

        if ($microtimers && count($microtimers) > 0) {
            foreach ($microtimers as $time) {
                $totalTime = $time['difference'];

                if (str_contains(strtolower($time['memoryusage']), 'nan')) {
                    $time['memoryusage'] = str_replace('NAN', '0', $time['memoryusage']);
                }

                $totalMemoryUsage = $time['memoryusage'];

                $method = str_replace('CheckIpFilter', '', $time['reference']);
            }
        }

        if (isset($totalTime) && isset($totalMemoryUsage) && isset($method)) {
            if (strtolower($method) === 'default') {
                $totalTime = $this->getTotalMicrotimer();
            }

            if ($method !== 'indexes') {
                $method = $method . ' database';
            }

            return $this->firewall->ip . ' address found in ' . $method . '. It took ' . $totalTime . '(s) and ' . $totalMemoryUsage . ' of memory.';
        }

        return '';
    }

    protected function resetMicroTimers()
    {
        $this->microtime = 0;
        $this->memoryusage = 0;
        $this->microTimers = [];
    }

    public function setMicroTimer($reference, $calculateMemoryUsage = false, $resetMicroTimers = false)
    {
        if ($resetMicroTimers) {
            $this->resetMicroTimers();
        }

        if (isset($this->microTimers[$reference])) {
            $microtime = $this->microTimers[$reference];
        } else {
            $microtime['reference'] = $reference;
        }

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

        $this->microTimers[$reference] = $microtime;
    }

    protected function getMemUsage($bytes)
    {
        $unit=array('b','kb','mb','gb','tb','pb');

        return @round(abs($bytes)/pow(1024,($i=floor(log(abs($bytes),1024)))),2).' '.$unit[$i];
    }
}