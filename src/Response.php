<?php

namespace PHPFirewall;

class Response
{
    public $response = [];

    public function getAllData()
    {
        return ['response' => $this->response];
    }

    public function __set($key, $value)
    {
        $this->response[$key] = $value;
    }

    public function __unset($key)
    {
        if (isset($this->response[$key])) {
            unset($this->response[$key]);
        }
    }

    public function __get($key)
    {
        if (isset($this->response[$key])) {
            return $this->response[$key];
        } else {
            throw new \Exception('Response key "' . $key . '" does not exists!');
        }
    }

    public function __isset($key)
    {
        return array_key_exists($key, $this->response);
    }

    public function reset()
    {
        $this->response = [];
    }
}