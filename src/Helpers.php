<?php

if (!function_exists('fwbase_path')) {
    function fwbase_path($path = '', $root = null) {
        if ($root) {
            return $root . '/..' . ($path ? DIRECTORY_SEPARATOR . $path : $path);
        }

        return __DIR__ . '/..' . ($path ? DIRECTORY_SEPARATOR . $path : $path);
    }
}