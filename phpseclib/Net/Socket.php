<?php

namespace phpseclib;

class Net_Socket
{
    protected $socket;

    public function open($host, $port, $timeout)
    {
        $this->socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$this->socket) {
            throw new \Exception("Cannot connect to $host. Error $errno. $errstr");
        }
    }

    public function isEof()
    {

        return feof($this->socket);
    }

    public function readLine($maxBytes)
    {

        return fgets($this->socket, $maxBytes);
    }

    public function readBytes($numBytes)
    {

        return fread($this->socket, $numBytes);
    }

    public function writeBytes($data)
    {

        return fputs($this->socket, $data);
    }

    /**
     * Test if the $socket is writable
     *
     * @param resource $socket the resource to be checked
     *
     * @return boolean TRUE on success, FALSE otherwise.
     */
    function isWritable()
    {
        $write = array($this->socket);
        $n = null;
        socket_select($n, $write, $n, 0);

        return (isset($write[0]) && $write[0] === $this->socket);
    }


}
