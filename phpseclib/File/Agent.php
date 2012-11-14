<?php
/**
 * Pure-PHP implementation of SSH-Agent.
 *
 * PHP versions 4 and 5
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category Net
 * @package  File
 * @author   Manuel 'Kea' Baldassarri <k3a@k3a.it>
 * @license  http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link     http://phpseclib.sourceforge.net
 */

namespace phpseclib;

define('FILE_AGENTC_REQUEST_IDENTITIES', 11);
define('FILE_AGENT_IDENTITIES_ANSWER', 12);
define('FILE_AGENTC_SIGN_REQUEST', 13);
define('FILE_AGENT_SIGN_RESPONSE', 14);

define('FILE_AGENTC_LOCK', 22); // SSH_AGENTC_LOCK
define('FILE_AGENTC_UNLOCK', 23); // SSH_AGENTC_UNLOCK

// SSH_AGENTC_REQUEST_RSA_IDENTITIES
define('FILE_AGENTC_REQUEST_RSA_IDENTITIES', 1);

 // SSH_AGENT_RSA_IDENTITIES_ANSWER
define('FILE_AGENT_RSA_IDENTITIES_ANSWER', 2);
 // SSH_AGENT_FAILURE
define('FILE_AGENT_FAILURE', 5);

/**
 * Pure-PHP implementation of SSH-Agent.
 *
 * @category Net
 * @package  Net_File
 * @author   Manuel 'Kea' Baldassarri <k3a@k3a.it>
 * @access   public
 */
class File_Agent
{
    /**
     * The socket connetion to ssh-agent
     *
     * @var Net_UnixSocket
     */
    protected $socket = null;

    /**
     * Store the last error occurred
     *
     * @see File_Agent::getLastError()
     * @var string
     */
    protected $lastError = false;

    /**
     * List of identities retrieved from ssh-agent
     *
     * @see File_Agent::getKeys()
     * @var Array
     */
    protected $keys = array();

    public function __construct(Net_UnixSocket $socket = null)
    {
        if (is_null($socket)) {
            $socket = new Net_UnixSocket();
        }

        $this->socket = $socket;
    }

    /**
     * Connects to the ssh-agent socket
     *
     * @return resource returns a socket resource on success, or FALSE on error.
     */
    function connect()
    {
        if ($this->socket instanceof Net_UnixSocket && $this->socket->isWritable()) {

            return true;
        }

        $address = null;

        if (isset($_SERVER['SSH_AUTH_SOCK'])) {
            $address = $_SERVER['SSH_AUTH_SOCK'];
        } elseif (isset($_ENV['SSH_AUTH_SOCK'])) {
            $address = $_ENV['SSH_AUTH_SOCK'];
        } else {
            $this->lastError = 'SSH_AUTH_SOCK not found.';

            return false;
        }

        if (!$this->socket->connect($address)) {
            $this->lastError = $this->socket->getLastError();

            return false;
        }

        return true;
    }

    /**
     * Retrieves all the identities added to ssh-agent
     *
     * @return boolean TRUE on success or FALSE on errors.
     */
    function requestIdentities()
    {
        if (!$this->sendRequest(FILE_AGENTC_REQUEST_IDENTITIES)) {
            user_error(
                'Unable to request identities '.socket_strerror(socket_last_error()),
                E_USER_NOTICE
            );

            return false;
        }

        $bufferLenght = $this->readLength();
        $type = $this->readType();

        if ($type == FILE_AGENT_FAILURE) {

            return false;
        } elseif (
            $type != FILE_AGENT_RSA_IDENTITIES_ANSWER &&
            $type != FILE_AGENT_IDENTITIES_ANSWER) {
            throw new \Exception("Unknown response from agent: $type");
        }

        $buffer = $this->socket->readBytes($bufferLenght - 1);
        $keysCount = $this->binaryToLong($buffer);
        $buffer = substr($buffer, 4);

        $this->keys = array();
        for ($i = 0; $i < $keysCount; ++$i) {
            $blob = $this->readPacketFromBuffer($buffer);
            $comment = $this->readPacketFromBuffer($buffer);

            /** @todo Check crypt method */
            $k = new Crypt_RSA();
            if (!$k->setPublicKey('ssh-rsa '.base64_encode($blob))) {
                user_error(
                    "Invalid key or key not supported: ".
                    $comment,
                    E_USER_NOTICE
                );

                continue;
            }

            $this->keys[] = $k;
            // The complete structure should be
            // $this->keys[] = array(
            //     'blob' => $blob,
            //     'comment' => $comment,
            //     'key' => $k);
        }

        return true;
    }

    /**
     * Converts long from binary rapresentation
     *
     * @param string $binary long binary rapresentation
     *
     * @return integer
     */
    static function binaryToLong($binary)
    {

        return current(unpack('Nlong', $binary));
    }

    /**
     * Sends request of type $type and optionally $data to ssh-agent
     *
     * @param char   $type the type of request
     * @param string $data data to be sent
     *
     * @return integer bytes written
     */
    function sendRequest($type, $data = '')
    {
        $len = strlen($data) + 1;
        $buffer = pack("NCa*", $len, $type, $data);

        return $this->socket->writeBytes($buffer);
    }

    /**
     * Reads a long integer from the current connection
     *
     * @return integer bytes read
     */
    function readLength()
    {
        $len = $this->socket->readBytes(4);

        return $this->binaryToLong($len);
    }

    /**
     * Reads the type of the response from the current connection
     *
     * @return integer
     */
    function readType()
    {

        return ord($this->socket->readBytes(1));
    }

    /**
     * Unpacks and removes a response from a string
     *
     * @param string &$buffer the source to unpack
     *
     * @return string
     */
    function readPacketFromBuffer(&$buffer)
    {
        $len = $this->binaryToLong($buffer);
        $packet = substr($buffer, 4, $len);
        $buffer = substr($buffer, $len + 4);

        return $packet;
    }

    /**
     * Gets keys
     *
     * @return array the identities
     */
    function getKeys()
    {

        return $this->keys;
    }

    /**
     * Sign $data with $pubkeydata via ssh-agent
     *
     * @param string $pubkeydata key used to sign
     * @param string $data       data to be signed
     *
     * @return boolean TRUE on success, FALSE otherwise.
     */
    function sign($pubkeydata, $data)
    {
        /* Create a request to sign the data */
        $s = pack(
            'CNa*Na*N',
            FILE_AGENTC_SIGN_REQUEST,
            strlen($pubkeydata),
            $pubkeydata,
            strlen($data),
            $data,
            0
        );

        if (!$this->socket->isWritable()) {
            throw new \Exception("Agent not connected");
        }

        $rc = $this->socket->writeBytes(pack("Na*", strlen($s), $s));

        if ($rc === false) {
            throw new \Exception('Unable to write to the socket: '.socket_strerror(socket_last_error()));
        }

        $len = $this->readLength();

        if ($len < 8) {
            throw new \Exception("Error protocol");
        }

        $type = $this->readType();

        if ($type != FILE_AGENT_SIGN_RESPONSE) {
            throw new \Exception("Error protocol");
        }

        $s = $this->socket->readBytes($len - 1);

        $signature = unpack('Nlen/a*blob', $s);

        if ($len != 5 + $signature['len']) {
            throw new \Exception("Invalid sign");
        }

        return $signature['blob'];
    }

    public function getLastError()
    {
        return $this->lastError;
    }
}
