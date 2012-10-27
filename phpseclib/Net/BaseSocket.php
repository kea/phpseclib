<?php
/**
 * Abstract socket class
 *
 * PHP versions 5.3+
 *
 * Class that extends this abstract class will handle all the details of socket
 * communications for Net_SSHx and related classes. This is so that we
 * can stub out all the over-the-wire stuff for unit testing.
 *
 */

namespace phpseclib;

abstract class Net_BaseSocket
{
    protected $socket;

    /**
     * MUST return a valid socket, or else throw an appropriate
     * exception
     */
    abstract public function open($host, $port, $timeout);

    public function isEof()
    {

        return false;
    }

    public function isWritable()
    {

        return true;
    }

    /**
     * Read from the socket until the first newline, or until
     * $maxBytes bytes have been read, whichever comes first.
     */
    abstract public function readLine($maxBytes);

    abstract public function readBytes($numBytes);

    abstract public function writeBytes($data);
}
