<?php

namespace phpseclib;

class Net_UnixSocket
{
    protected $socket;
    protected $lastError;

    public function connect($address)
    {
        $this->socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
        if ($this->socket === false ||
            is_null($address) ||
            !socket_connect($this->socket, $address)) {
            $this->lastError = sprintf("Cannot connect to %s:%d. Error %s: %s",
                $host, $port, socket_last_error(),
                socket_strerror(socket_last_error()));

            return false;
        }

        return true;
    }

    public function readLine($maxBytes)
    {

        return fgets($this->socket, $maxBytes);
    }

    public function readBytes($numBytes)
    {

        return socket_read($this->socket, $numBytes);
    }

    public function writeBytes($data)
    {

        return socket_write($this->socket, $data);
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
        if (empty($this->socket)) {

            return false;
        }

        $write = array($this->socket);
        $n = null;
        socket_select($n, $write, $n, 0);

        return (isset($write[0]) && $write[0] === $this->socket);
    }

    public function getLastError()
    {
        return $this->lastError;
    }
}
