<?php

/**
 * @Project e.com.vn
 * @Author vndes.net
 
 
 * @Createdate 1-27-2010 5:25
 */
namespace Vndes\Core;

class Ips
{

    public $client_ip;

    public $forward_ip;

    public $remote_addr;

    public $remote_ip;

    public $is_proxy = 0;

    /**
     * ips::__construct()
     *
     * @param mixed $db_config
     * @return
     *
     */
    public function __construct()
    {
        $this->client_ip = trim($this->e_get_clientip());
        $this->forward_ip = trim($this->e_get_forwardip());
        $this->remote_addr = trim($this->e_get_remote_addr());
        $this->remote_ip = trim($this->e_getip());
    }

    /**
     * ips::e_getenv()
     *
     * @param mixed $key
     * @return
     *
     */
    private function e_getenv($key)
    {
        if (isset($_SERVER[$key])) {
            return $_SERVER[$key];
        } elseif (isset($_ENV[$key])) {
            return $_ENV[$key];
        } elseif (@getenv($key)) {
            return @getenv($key);
        } elseif (function_exists('apache_getenv') && apache_getenv($key, true)) {
            return apache_getenv($key, true);
        }
        return '';
    }

    /**
     * ips::e_validip()
     *
     * @param mixed $ip
     * @return
     *
     */
    public function e_validip($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }

    /**
     * ips::server_ip()
     *
     * @return
     *
     */
    public function server_ip()
    {
        $serverip = $this->e_getenv('SERVER_ADDR');
        if ($this->e_validip($serverip)) {
            return $serverip;
        } elseif ($_SERVER['SERVER_NAME'] == 'localhost') {
            return '127.0.0.1';
        } elseif (function_exists('gethostbyname')) {
            return gethostbyname($_SERVER['SERVER_NAME']);
        }
        return 'none';
    }

    /**
     * ips::e_get_clientip()
     *
     * @return
     *
     */
    private function e_get_clientip()
    {
        $clientip = '';
        if ($this->e_getenv('HTTP_CLIENT_IP')) {
            $clientip = $this->e_getenv('HTTP_CLIENT_IP');
        } elseif ($this->e_getenv('HTTP_VIA')) {
            $clientip = $this->e_getenv('HTTP_VIA');
        } elseif ($this->e_getenv('HTTP_X_COMING_FROM')) {
            $clientip = $this->e_getenv('HTTP_X_COMING_FROM');
        } elseif ($this->e_getenv('HTTP_COMING_FROM')) {
            $clientip = $this->e_getenv('HTTP_COMING_FROM');
        }

        if ($this->e_validip($clientip)) {
            return $clientip;
        } else {
            return 'none';
        }
    }

    /**
     * ips::e_get_forwardip()
     *
     * @return
     *
     */
    private function e_get_forwardip()
    {
        if ($this->e_getenv('HTTP_X_FORWARDED_FOR') and $this->e_validip($this->e_getenv('HTTP_X_FORWARDED_FOR'))) {
            return $this->e_getenv('HTTP_X_FORWARDED_FOR');
        } elseif ($this->e_getenv('HTTP_X_FORWARDED') and $this->e_validip($this->e_getenv('HTTP_X_FORWARDED'))) {
            return $this->e_getenv('HTTP_X_FORWARDED');
        } elseif ($this->e_getenv('HTTP_FORWARDED_FOR') and $this->e_validip($this->e_getenv('HTTP_FORWARDED_FOR'))) {
            return $this->e_getenv('HTTP_FORWARDED_FOR');
        } elseif ($this->e_getenv('HTTP_FORWARDED') and $this->e_validip($this->e_getenv('HTTP_FORWARDED'))) {
            return $this->e_getenv('HTTP_FORWARDED');
        } else {
            return 'none';
        }
    }

    /**
     * ips::e_get_remote_addr()
     *
     * @return
     *
     */
    private function e_get_remote_addr()
    {
        if ($this->e_getenv('REMOTE_ADDR') and $this->e_validip($this->e_getenv('REMOTE_ADDR'))) {
            return $this->e_getenv('REMOTE_ADDR');
        }
        return 'none';
    }

    /**
     * ips::e_getip()
     *
     * @return
     *
     */
    private function e_getip()
    {
        if ($this->client_ip != 'none') {
            return $this->client_ip;
        }
        if ($this->forward_ip != 'none') {
            return $this->forward_ip;
        }
        if ($this->remote_addr != 'none') {
            return $this->remote_addr;
        }

        if ($_SERVER['SERVER_NAME'] == 'localhost') {
            return '127.0.0.1';
        }
        return 'none';
    }

    /**
     * ips::e_chech_proxy()
     *
     * @return
     *
     */
    public function e_check_proxy()
    {
        $proxy = 'No';
        if ($this->client_ip != 'none' || $this->forward_ip != 'none') {
            $proxy = 'Lite';
        }
        $host = @getHostByAddr($this->remote_ip);
        if (stristr($host, 'proxy')) {
            $proxy = 'Mild';
        }
        if ($this->remote_ip == $host) {
            $proxy = 'Strong';
        }
        return $proxy;
    }
}
