<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Pure-PHP implementation of SSHv2.
 *
 * PHP versions 5.3+
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include('Net/SSH2.php');
 *
 *    $ssh = new Net_SSH2('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * <code>
 * <?php
 *    include('Crypt/RSA.php');
 *    include('Net/SSH2.php');
 *
 *    $key = new Crypt_RSA();
 *    //$key->setPassword('whatever');
 *    $key->loadKey(file_get_contents('privatekey'));
 *
 *    $ssh = new Net_SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $key)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->read('username@username:~$');
 *    $ssh->write("ls -la\n");
 *    echo $ssh->read('username@username:~$');
 * ?>
 * </code>
 *
 * <code>
 * <?php
 *    include('Net/SSH2.php');
 *    include('File/Agent.php');
 *
 *    $agent = new File_Agent();
 *    $ssh = new Net_SSH2('localhost');
 *    if (!$ssh->login('username', $agent)) {
 *      exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 * ?>
 * </code>
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
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
 * @category   Net
 * @package    Net_SSH2
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @version    $Id: SSH2.php,v 1.53 2010-10-24 01:24:30 terrafrost Exp $
 * @link       http://phpseclib.sourceforge.net
 */

namespace phpseclib;

/**
 * Pure-PHP implementation of SSHv2.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.1.0
 * @access  public
 * @package Net_SSH2
 */
class Net_SSH2 {

    /**#@+
     * Execution Bitmap Masks
     *
     * @see Net_SSH2::bitmap
     * @access private
     */
    const MASK_CONSTRUCTOR = 0x00000001;
    const MASK_LOGIN       = 0x00000002;
    const MASK_SHELL       = 0x00000004;
    
    /**#@+
     * Channel constants
     *
     * RFC4254 refers not to client and server channels but rather to sender and recipient channels.  we don't refer
     * to them in that way because RFC4254 toggles the meaning. the client sends a SSH_MSG_CHANNEL_OPEN message with
     * a sender channel and the server sends a SSH_MSG_CHANNEL_OPEN_CONFIRMATION in response, with a sender and a
     * recepient channel.  at first glance, you might conclude that SSH_MSG_CHANNEL_OPEN_CONFIRMATION's sender channel
     * would be the same thing as SSH_MSG_CHANNEL_OPEN's sender channel, but it's not, per this snipet:
     *     The 'recipient channel' is the channel number given in the original
     *     open request, and 'sender channel' is the channel number allocated by
     *     the other side.
     *
     * @see Net_SSH2::_send_channel_packet()
     * @see Net_SSH2::_get_channel_packet()
     * @access private
     */
    const CHANNEL_EXEC  = 0; // PuTTy uses 0x100
    const CHANNEL_SHELL = 1;
    
    /**
     * Returns the message numbers
     */
    const LOG_SIMPLE = 1;

    /**
     * Returns the message content
     */
    const LOG_COMPLEX = 2;

    /**
     * Outputs the content real-time
     */

    const LOG_REALTIME = 3;
    /**
     * Dumps the content real-time to a file
     */
    const LOG_REALTIME_FILE = 4;    
    
    /**
     * Returns when a string matching $expect exactly is found
     */
    const READ_SIMPLE = 1;

    /**
     * Returns when a string matching the regular expression $expect is found
     */
    const READ_REGEX = 2;

    /**
     * Make sure that the log never gets larger than this
     */
    const LOG_MAX_SIZE = 1048576;
    
    /**
     * Used when a Crypt_RSA object is passed as the second parameter of login()
     */
    const PRIVKEY_MODE_RSA = 0;

    /**
     * Used when a File_Agent object is passed as the second parameter of login()
     */
    const PRIVKEY_MODE_AGENT = 1;

    /**
     * SSH Message constants
     */
    const MSG_DISCONNECT                 = 1;
    const MSG_IGNORE                     = 2;
    const MSG_UNIMPLEMENTED              = 3;
    const MSG_DEBUG                      = 4;
    const MSG_SERVICE_REQUEST            = 5;
    const MSG_SERVICE_ACCEPT             = 6;
    const MSG_KEXINIT                    = 20;
    const MSG_NEWKEYS                    = 21;
    const MSG_KEXDH_INIT                 = 30;
    const MSG_KEXDH_REPLY                = 31;
    const MSG_USERAUTH_REQUEST           = 50;
    const MSG_USERAUTH_FAILURE           = 51;
    const MSG_USERAUTH_SUCCESS           = 52;
    const MSG_USERAUTH_BANNER            = 53;
    const MSG_USERAUTH_PASSWD_CHANGEREQ  = 60;
    const MSG_USERAUTH_PK_OK             = 60;
    const MSG_USERAUTH_INFO_REQUEST      = 60;
    const MSG_USERAUTH_INFO_RESPONSE     = 61;
    const MSG_GLOBAL_REQUEST             = 80;
    const MSG_REQUEST_SUCCESS            = 81;
    const MSG_REQUEST_FAILURE            = 82;
    const MSG_CHANNEL_OPEN               = 90;
    const MSG_CHANNEL_OPEN_CONFIRMATION  = 91;
    const MSG_CHANNEL_OPEN_FAILURE       = 92;
    const MSG_CHANNEL_WINDOW_ADJUST      = 93;
    const MSG_CHANNEL_DATA               = 94;
    const MSG_CHANNEL_EXTENDED_DATA      = 95;
    const MSG_CHANNEL_EOF                = 96;
    const MSG_CHANNEL_CLOSE              = 97;
    const MSG_CHANNEL_REQUEST            = 98;
    const MSG_CHANNEL_SUCCESS            = 99;
    const MSG_CHANNEL_FAILURE            = 100;

    /**
     * SSH Disconnect constants
     */
    const DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    = 1;
    const DISCONNECT_PROTOCOL_ERROR                 = 2;
    const DISCONNECT_KEY_EXCHANGE_FAILED            = 3;
    const DISCONNECT_RESERVED                       = 4;
    const DISCONNECT_MAC_ERROR                      = 5;
    const DISCONNECT_COMPRESSION_ERROR              = 6;
    const DISCONNECT_SERVICE_NOT_AVAILABLE          = 7;
    const DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    const DISCONNECT_HOST_KEY_NOT_VERIFIABLE        = 9;
    const DISCONNECT_CONNECTION_LOST                = 10;
    const DISCONNECT_BY_APPLICATION                 = 11;
    const DISCONNECT_TOO_MANY_CONNECTIONS           = 12;
    const DISCONNECT_AUTH_CANCELLED_BY_USER         = 13;
    const DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    const DISCONNECT_ILLEGAL_USER_NAME              = 15;

    /**
     * Channel Open Failure Constants
     */
    const OPEN_ADMINISTRATIVELY_PROHIBITED = 1;

    /**
     * Terminal Modes Constants
     */
    const TTY_OP_END = 0;
    
    /**
     * Channel Extended Data Type Constants
     */
    const EXTENDED_DATA_STDERR = 1;

    /**
     * The SSH identifier
     *
     * @var String
     */
    private $identifier = 'SSH-2.0-phpseclib_0.3';

    /**
     * The Socket Object
     *
     * @var BaseSocket
     */
    private $fsock;

    /**
     * Execution Bitmap
     *
     * The bits that are set represent functions that have been called already.  This is used to determine
     * if a requisite function has been successfully executed.  If not, an error should be thrown.
     *
     * @var Integer
     */
    private $bitmap = 0;

    /**
     * Error information
     *
     * @see Net_SSH2::getErrors()
     * @see Net_SSH2::getLastError()
     * @var String
     */
    private $errors = array();

    /**
     * Server Identifier
     *
     * @see Net_SSH2::getServerIdentification()
     * @var String
     */
    private $server_identifier = '';

    /**
     * Key Exchange Algorithms
     *
     * @see Net_SSH2::getKexAlgorithims()
     * @var Array
     */
    private $kex_algorithms;

    /**
     * Server Host Key Algorithms
     *
     * @see Net_SSH2::getServerHostKeyAlgorithms()
     * @var Array
     */
    private $server_host_key_algorithms;

    /**
     * Encryption Algorithms: Client to Server
     *
     * @see Net_SSH2::getEncryptionAlgorithmsClient2Server()
     * @var Array
     */
    private $encryption_algorithms_client_to_server;

    /**
     * Encryption Algorithms: Server to Client
     *
     * @see Net_SSH2::getEncryptionAlgorithmsServer2Client()
     * @var Array
     */
    private $encryption_algorithms_server_to_client;

    /**
     * MAC Algorithms: Client to Server
     *
     * @see Net_SSH2::getMACAlgorithmsClient2Server()
     * @var Array
     */
    private $mac_algorithms_client_to_server;

    /**
     * MAC Algorithms: Server to Client
     *
     * @see Net_SSH2::getMACAlgorithmsServer2Client()
     * @var Array
     */
    private $mac_algorithms_server_to_client;

    /**
     * Compression Algorithms: Client to Server
     *
     * @see Net_SSH2::getCompressionAlgorithmsClient2Server()
     * @var Array
     */
    private $compression_algorithms_client_to_server;

    /**
     * Compression Algorithms: Server to Client
     *
     * @see Net_SSH2::getCompressionAlgorithmsServer2Client()
     * @var Array
     */
    private $compression_algorithms_server_to_client;

    /**
     * Languages: Server to Client
     *
     * @see Net_SSH2::getLanguagesServer2Client()
     * @var Array
     */
    private $languages_server_to_client;

    /**
     * Languages: Client to Server
     *
     * @see Net_SSH2::getLanguagesClient2Server()
     * @var Array
     */
    private $languages_client_to_server;

    /**
     * Block Size for Server to Client Encryption
     *
     * "Note that the length of the concatenation of 'packet_length',
     *  'padding_length', 'payload', and 'random padding' MUST be a multiple
     *  of the cipher block size or 8, whichever is larger.  This constraint
     *  MUST be enforced, even when using stream ciphers."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-6
     *
     * @see Net_SSH2::Net_SSH2()
     * @see Net_SSH2::_send_binary_packet()
     * @var Integer
     */
    private $encrypt_block_size = 8;

    /**
     * Block Size for Client to Server Encryption
     *
     * @see Net_SSH2::Net_SSH2()
     * @see Net_SSH2::_get_binary_packet()
     * @var Integer
     */
    private $decrypt_block_size = 8;

    /**
     * Server to Client Encryption Object
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Object
     */
    private $decrypt = false;

    /**
     * Client to Server Encryption Object
     *
     * @see Net_SSH2::_send_binary_packet()
     * @var Object
     */
    private $encrypt = false;

    /**
     * Client to Server HMAC Object
     *
     * @see Net_SSH2::_send_binary_packet()
     * @var Object
     */
    private $hmac_create = false;

    /**
     * Server to Client HMAC Object
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Object
     */
    private $hmac_check = false;

    /**
     * Size of server to client HMAC
     *
     * We need to know how big the HMAC will be for the server to client direction so that we know how many bytes to read.
     * For the client to server side, the HMAC object will make the HMAC as long as it needs to be.  All we need to do is
     * append it.
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Integer
     */
    private $hmac_size = false;

    /**
     * Server Public Host Key
     *
     * @see Net_SSH2::getServerPublicHostKey()
     * @var String
     */
    private $server_public_host_key;

    /**
     * Session identifer
     *
     * "The exchange hash H from the first key exchange is additionally
     *  used as the session identifier, which is a unique identifier for
     *  this connection."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-7.2
     *
     * @see Net_SSH2::_key_exchange()
     * @var String
     */
    private $session_id = false;

    /**
     * Exchange hash
     *
     * The current exchange hash
     *
     * @see Net_SSH2::_key_exchange()
     * @var String
     */
    private $exchange_hash = false;

    /**
     * Message Numbers
     *
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     */
    private $message_numbers = array();

    /**
     * Disconnection Message 'reason codes' defined in RFC4253
     *
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     */
    private $disconnect_reasons = array();

    /**
     * SSH_MSG_CHANNEL_OPEN_FAILURE 'reason codes', defined in RFC4254
     *
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     */
    private $channel_open_failure_reasons = array();

    /**
     * Terminal Modes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-8
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     */
    private $terminal_modes = array();

    /**
     * SSH_MSG_CHANNEL_EXTENDED_DATA's data_type_codes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-5.2
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     */
    private $channel_extended_data_type_codes = array();

    /**
     * Send Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see Net_SSH2::_send_binary_packet()
     * @var Integer
     */
    private $send_seq_no = 0;

    /**
     * Get Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Integer
     */
    private $get_seq_no = 0;

    /**
     * Server Channels
     *
     * Maps client channels to server channels
     *
     * @see Net_SSH2::_get_channel_packet()
     * @see Net_SSH2::exec()
     * @var Array
     */
    private $server_channels = array();

    /**
     * Channel Buffers
     *
     * If a client requests a packet from one channel but receives two packets from another those packets should
     * be placed in a buffer
     *
     * @see Net_SSH2::_get_channel_packet()
     * @see Net_SSH2::exec()
     * @var Array
     */
    private $channel_buffers = array();

    /**
     * Channel Status
     *
     * Contains the type of the last sent message
     *
     * @see Net_SSH2::_get_channel_packet()
     * @var Array
     */
    private $channel_status = array();

    /**
     * Packet Size
     *
     * Maximum packet size indexed by channel
     *
     * @see Net_SSH2::_send_channel_packet()
     * @var Array
     */
    private $packet_size_client_to_server = array();

    /**
     * Message Number Log
     *
     * @see Net_SSH2::getLog()
     * @var Array
     */
    private $message_number_log = array();

    /**
     * Message Log
     *
     * @see Net_SSH2::getLog()
     * @var Array
     */
    private $message_log = array();

    /**
     * The Window Size
     *
     * Bytes the other party can send before it must wait for the window to be adjusted (0x7FFFFFFF = 4GB)
     *
     * @var Integer
     * @see Net_SSH2::_send_channel_packet()
     * @see Net_SSH2::exec()
     */
    private $window_size = 0x7FFFFFFF;

    /**
     * Window size
     *
     * Window size indexed by channel
     *
     * @see Net_SSH2::_send_channel_packet()
     * @var Array
     */
    private $window_size_client_to_server = array();

    /**
     * Server signature
     *
     * Verified against $this->session_id
     *
     * @see Net_SSH2::getServerPublicHostKey()
     * @var String
     */
    private $signature = '';

    /**
     * Server signature format
     *
     * ssh-rsa or ssh-dss.
     *
     * @see Net_SSH2::getServerPublicHostKey()
     * @var String
     */
    private $signature_format = '';

    /**
     * Interactive Buffer
     *
     * @see Net_SSH2::read()
     * @var Array
     */
    private $interactiveBuffer = '';

    /**
     * Current log size
     *
     * Should never exceed self::LOG_MAX_SIZE
     *
     * @see Net_SSH2::_send_binary_packet()
     * @see Net_SSH2::_get_binary_packet()
     * @var Integer
     */
    private $log_size;

    /**
     * Timeout
     *
     * @see Net_SSH2::setTimeout()
     */
    private $timeout;

    /**
     * Current Timeout
     *
     * @see Net_SSH2::_get_channel_packet()
     */
    private $curTimeout;

    /**
     * Real-time log file pointer
     *
     * @see Net_SSH2::_append_log()
     */
    private $realtime_log_file;

    /**
     * Real-time log file size
     *
     * @see Net_SSH2::_append_log()
     */
    private $realtime_log_size;

    /**
     * Has the signature been validated?
     *
     * @see Net_SSH2::getServerPublicHostKey()
     */
    private $signature_validated = false;

    /**
     * Real-time log file wrap boolean
     *
     * @see Net_SSH2::_append_log()
     */
    private $realtime_log_wrap;

    /**
     * Flag to suppress stderr from output
     *
     * @see Net_SSH2::enableQuietMode()
     */
    private $quiet_mode = false;

    /**
     * SSH Agent object
     *
     * @see Net_SSH2::_ssh_agent_login()
     */
    private $agent;

    /**
     * Whether logging is on/off
     * 
     * @see setLogging()
     */
    public static $logging = false;

    /**
     * Default Constructor.
     *
     * Connects to an SSHv2 server
     *
     * @param String $host
     * @param optional Integer $port
     * @param optional Integer $timeout
     * @return Net_SSH2
     * @access public
     */
    function __construct($host, $port = 22, $timeout = 10)
    {
        $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
        $this->fsock = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$this->fsock) {
            throw new \Exception(rtrim("Cannot connect to $host. Error $errno. $errstr"));
        }
        $elapsed = strtok(microtime(), ' ') + strtok('') - $start;

        $timeout-= $elapsed;

        if ($timeout <= 0) {
            throw new \Exception(rtrim("Cannot connect to $host. Timeout error"), E_USER_NOTICE);
        }

        $read = array($this->fsock);
        $write = $except = NULL;

        $sec = floor($timeout);
        $usec = 1000000 * ($timeout - $sec);

        // on windows this returns a "Warning: Invalid CRT parameters detected" error
        // the !count() is done as a workaround for <https://bugs.php.net/42682>
        if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
            throw new \Exception(rtrim("Cannot connect to $host. Banner timeout"), E_USER_NOTICE);
        }

        /* According to the SSH2 specs,

          "The server MAY send other lines of data before sending the version
           string.  Each line SHOULD be terminated by a Carriage Return and Line
           Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
           in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
           MUST be able to process such lines." */
        $temp = '';
        $extra = '';
        while (!feof($this->fsock) && !preg_match('#^SSH-(\d\.\d+)#', $temp, $matches)) {
            if (substr($temp, -2) == "\r\n") {
                $extra.= $temp;
                $temp = '';
            }
            $temp.= fgets($this->fsock, 255);
        }

        if (feof($this->fsock)) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        $ext = array();
        if (extension_loaded('mcrypt')) {
            $ext[] = 'mcrypt';
        }
        if (extension_loaded('gmp')) {
            $ext[] = 'gmp';
        } else if (extension_loaded('bcmath')) {
            $ext[] = 'bcmath';
        }

        if (!empty($ext)) {
            $this->identifier.= ' (' . implode(', ', $ext) . ')';
        }

        if (self::$logging) {
            $this->message_number_log[] = '<-';
            $this->message_number_log[] = '->';

            if (self::$logging == self::LOG_COMPLEX) {
                $this->message_log[] = $extra . $temp;
                $this->message_log[] = $this->identifier . "\r\n";
            }
        }

        $this->server_identifier = trim($temp, "\r\n");
        if (!empty($extra)) {
            $this->errors[] = utf8_decode($extra);
        }

        if ($matches[1] != '1.99' && $matches[1] != '2.0') {
            throw new \Exception("Cannot connect to SSH $matches[1] servers", E_USER_NOTICE);
        }

        fputs($this->fsock, $this->identifier . "\r\n");

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        if (ord($response[0]) != self::MSG_KEXINIT) {
            throw new \Exception('Expected SSH_MSG_KEXINIT', E_USER_NOTICE);
        }

        if (!$this->_key_exchange($response)) {
            return;
        }

        $this->bitmap = self::MASK_CONSTRUCTOR;
    }

    /**
     * Key Exchange
     *
     * @param String $kexinit_payload_server
     * @access private
     */
    function _key_exchange($kexinit_payload_server)
    {
        static $kex_algorithms = array(
            'diffie-hellman-group1-sha1', // REQUIRED
            'diffie-hellman-group14-sha1' // REQUIRED
        );

        static $server_host_key_algorithms = array(
            'ssh-rsa', // RECOMMENDED  sign   Raw RSA Key
            'ssh-dss'  // REQUIRED     sign   Raw DSS Key
        );

        static $encryption_algorithms = array(
            // from <http://tools.ietf.org/html/rfc4345#section-4>:
            'arcfour256',
            'arcfour128',

            'arcfour',    // OPTIONAL          the ARCFOUR stream cipher with a 128-bit key

            'aes128-cbc', // RECOMMENDED       AES with a 128-bit key
            'aes192-cbc', // OPTIONAL          AES with a 192-bit key
            'aes256-cbc', // OPTIONAL          AES in CBC mode, with a 256-bit key

            // from <http://tools.ietf.org/html/rfc4344#section-4>:
            'aes128-ctr', // RECOMMENDED       AES (Rijndael) in SDCTR mode, with 128-bit key
            'aes192-ctr', // RECOMMENDED       AES with 192-bit key
            'aes256-ctr', // RECOMMENDED       AES with 256-bit key
            '3des-ctr',   // RECOMMENDED       Three-key 3DES in SDCTR mode

            '3des-cbc',   // REQUIRED          three-key 3DES in CBC mode
            'none'        // OPTIONAL          no encryption; NOT RECOMMENDED
        );

        static $mac_algorithms = array(
            'hmac-sha1-96', // RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
            'hmac-sha1',    // REQUIRED        HMAC-SHA1 (digest length = key length = 20)
            'hmac-md5-96',  // OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
            'hmac-md5',     // OPTIONAL        HMAC-MD5 (digest length = key length = 16)
            'none'          // OPTIONAL        no MAC; NOT RECOMMENDED
        );

        static $compression_algorithms = array(
            'none'   // REQUIRED        no compression
            //'zlib' // OPTIONAL        ZLIB (LZ77) compression
        );

        // some SSH servers have buggy implementations of some of the above algorithms
        switch ($this->server_identifier) {
            case 'SSH-2.0-SSHD':
                $mac_algorithms = array_values(array_diff(
                    $mac_algorithms,
                    array('hmac-sha1-96', 'hmac-md5-96')
                ));
        }

        static $str_kex_algorithms, $str_server_host_key_algorithms,
               $encryption_algorithms_server_to_client, $mac_algorithms_server_to_client, $compression_algorithms_server_to_client,
               $encryption_algorithms_client_to_server, $mac_algorithms_client_to_server, $compression_algorithms_client_to_server;

        if (empty($str_kex_algorithms)) {
            $str_kex_algorithms = implode(',', $kex_algorithms);
            $str_server_host_key_algorithms = implode(',', $server_host_key_algorithms);
            $encryption_algorithms_server_to_client = $encryption_algorithms_client_to_server = implode(',', $encryption_algorithms);
            $mac_algorithms_server_to_client = $mac_algorithms_client_to_server = implode(',', $mac_algorithms);
            $compression_algorithms_server_to_client = $compression_algorithms_client_to_server = implode(',', $compression_algorithms);
        }

        $client_cookie = '';
        for ($i = 0; $i < 16; $i++) {
            $client_cookie.= chr(Crypt_Random::generateRandom(0, 255));
        }

        $response = $kexinit_payload_server;
        $this->_string_shift($response, 1); // skip past the message number (it should be SSH_MSG_KEXINIT)
        $server_cookie = $this->_string_shift($response, 16);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->kex_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->server_host_key_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->encryption_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->encryption_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->mac_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->mac_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->compression_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->compression_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->languages_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->languages_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        extract(unpack('Cfirst_kex_packet_follows', $this->_string_shift($response, 1)));
        $first_kex_packet_follows = $first_kex_packet_follows != 0;

        // the sending of SSH2_MSG_KEXINIT could go in one of two places.  this is the second place.
        $kexinit_payload_client = pack('Ca*Na*Na*Na*Na*Na*Na*Na*Na*Na*Na*CN',
            self::MSG_KEXINIT, $client_cookie, strlen($str_kex_algorithms), $str_kex_algorithms,
            strlen($str_server_host_key_algorithms), $str_server_host_key_algorithms, strlen($encryption_algorithms_client_to_server),
            $encryption_algorithms_client_to_server, strlen($encryption_algorithms_server_to_client), $encryption_algorithms_server_to_client,
            strlen($mac_algorithms_client_to_server), $mac_algorithms_client_to_server, strlen($mac_algorithms_server_to_client),
            $mac_algorithms_server_to_client, strlen($compression_algorithms_client_to_server), $compression_algorithms_client_to_server,
            strlen($compression_algorithms_server_to_client), $compression_algorithms_server_to_client, 0, '', 0, '',
            0, 0
        );

        if (!$this->_send_binary_packet($kexinit_payload_client)) {
            return false;
        }
        // here ends the second place.

        // we need to decide upon the symmetric encryption algorithms before we do the diffie-hellman key exchange
        for ($i = 0; $i < count($encryption_algorithms) && !in_array($encryption_algorithms[$i], $this->encryption_algorithms_server_to_client); $i++);
        if ($i == count($encryption_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible server to client encryption algorithms found', E_USER_NOTICE);
        }

        // we don't initialize any crypto-objects, yet - we do that, later. for now, we need the lengths to make the
        // diffie-hellman key exchange as fast as possible
        $decrypt = $encryption_algorithms[$i];
        switch ($decrypt) {
            case '3des-cbc':
            case '3des-ctr':
                $decryptKeyLength = 24; // eg. 192 / 8
                break;
            case 'aes256-cbc':
            case 'aes256-ctr':
                $decryptKeyLength = 32; // eg. 256 / 8
                break;
            case 'aes192-cbc':
            case 'aes192-ctr':
                $decryptKeyLength = 24; // eg. 192 / 8
                break;
            case 'aes128-cbc':
            case 'aes128-ctr':
                $decryptKeyLength = 16; // eg. 128 / 8
                break;
            case 'arcfour':
            case 'arcfour128':
                $decryptKeyLength = 16; // eg. 128 / 8
                break;
            case 'arcfour256':
                $decryptKeyLength = 32; // eg. 128 / 8
                break;
            case 'none';
                $decryptKeyLength = 0;
        }

        for ($i = 0; $i < count($encryption_algorithms) && !in_array($encryption_algorithms[$i], $this->encryption_algorithms_client_to_server); $i++);
        if ($i == count($encryption_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible client to server encryption algorithms found', E_USER_NOTICE);
        }

        $encrypt = $encryption_algorithms[$i];
        switch ($encrypt) {
            case '3des-cbc':
            case '3des-ctr':
                $encryptKeyLength = 24;
                break;
            case 'aes256-cbc':
            case 'aes256-ctr':
                $encryptKeyLength = 32;
                break;
            case 'aes192-cbc':
            case 'aes192-ctr':
                $encryptKeyLength = 24;
                break;
            case 'aes128-cbc':
            case 'aes128-ctr':
                $encryptKeyLength = 16;
                break;
            case 'arcfour':
            case 'arcfour128':
                $encryptKeyLength = 16;
                break;
            case 'arcfour256':
                $encryptKeyLength = 32;
                break;
            case 'none';
                $encryptKeyLength = 0;
        }

        $keyLength = $decryptKeyLength > $encryptKeyLength ? $decryptKeyLength : $encryptKeyLength;

        // through diffie-hellman key exchange a symmetric key is obtained
        for ($i = 0; $i < count($kex_algorithms) && !in_array($kex_algorithms[$i], $this->kex_algorithms); $i++);
        if ($i == count($kex_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible key exchange algorithms found', E_USER_NOTICE);
        }

        switch ($kex_algorithms[$i]) {
            // see http://tools.ietf.org/html/rfc2409#section-6.2 and
            // http://tools.ietf.org/html/rfc2412, appendex E
            case 'diffie-hellman-group1-sha1':
                $p = pack('H256', 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
                                  '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
                                  '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                                  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF');
                $keyLength = $keyLength < 160 ? $keyLength : 160;
                $hash = 'sha1';
                break;
            // see http://tools.ietf.org/html/rfc3526#section-3
            case 'diffie-hellman-group14-sha1':
                $p = pack('H512', 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
                                  '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
                                  '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                                  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
                                  '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
                                  '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
                                  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
                                  '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');
                $keyLength = $keyLength < 160 ? $keyLength : 160;
                $hash = 'sha1';
        }

        $p = new Math_BigInteger($p, 256);
        //$q = $p->bitwise_rightShift(1);

        /* To increase the speed of the key exchange, both client and server may
           reduce the size of their private exponents.  It should be at least
           twice as long as the key material that is generated from the shared
           secret.  For more details, see the paper by van Oorschot and Wiener
           [VAN-OORSCHOT].

           -- http://tools.ietf.org/html/rfc4419#section-6.2 */
        $q = new Math_BigInteger(1);
        $q = $q->bitwise_leftShift(2 * $keyLength);
        $q = $q->subtract(new Math_BigInteger(1));

        $g = new Math_BigInteger(2);
        $x = new Math_BigInteger();
        $x->setRandomGenerator('phpseclib\Crypt_Random::generateRandom');
        $x = $x->random(new Math_BigInteger(1), $q);
        $e = $g->modPow($x, $p);

        $eBytes = $e->toBytes(true);
        $data = pack('CNa*', self::MSG_KEXDH_INIT, strlen($eBytes), $eBytes);

        if (!$this->_send_binary_packet($data)) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }
        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        if ($type != self::MSG_KEXDH_REPLY) {
            throw new \Exception('Expected SSH_MSG_KEXDH_REPLY', E_USER_NOTICE);
        }

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->server_public_host_key = $server_public_host_key = $this->_string_shift($response, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
        $public_key_format = $this->_string_shift($server_public_host_key, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $fBytes = $this->_string_shift($response, $temp['length']);
        $f = new Math_BigInteger($fBytes, -256);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->signature = $this->_string_shift($response, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($this->signature, 4));
        $this->signature_format = $this->_string_shift($this->signature, $temp['length']);

        $key = $f->modPow($x, $p);
        $keyBytes = $key->toBytes(true);

        $this->exchange_hash = pack('Na*Na*Na*Na*Na*Na*Na*Na*',
            strlen($this->identifier), $this->identifier, strlen($this->server_identifier), $this->server_identifier,
            strlen($kexinit_payload_client), $kexinit_payload_client, strlen($kexinit_payload_server),
            $kexinit_payload_server, strlen($this->server_public_host_key), $this->server_public_host_key, strlen($eBytes),
            $eBytes, strlen($fBytes), $fBytes, strlen($keyBytes), $keyBytes
        );

        $this->exchange_hash = pack('H*', $hash($this->exchange_hash));

        if ($this->session_id === false) {
            $this->session_id = $this->exchange_hash;
        }

        for ($i = 0; $i < count($server_host_key_algorithms) && !in_array($server_host_key_algorithms[$i], $this->server_host_key_algorithms); $i++);
        if ($i == count($server_host_key_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible server host key algorithms found', E_USER_NOTICE);
        }

        if ($public_key_format != $server_host_key_algorithms[$i] || $this->signature_format != $server_host_key_algorithms[$i]) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('Sever Host Key Algorithm Mismatch', E_USER_NOTICE);
        }

        $packet = pack('C',
            self::MSG_NEWKEYS
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();

        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        if ($type != self::MSG_NEWKEYS) {
            throw new \Exception('Expected SSH_MSG_NEWKEYS', E_USER_NOTICE);
        }

        switch ($encrypt) {
            case '3des-cbc':
                $this->encrypt = new Crypt_TripleDES();
                // $this->encrypt_block_size = 64 / 8 == the default
                break;
            case '3des-ctr':
                $this->encrypt = new Crypt_TripleDES(Crypt_DES::MODE_CTR);
                // $this->encrypt_block_size = 64 / 8 == the default
                break;
            case 'aes256-cbc':
            case 'aes192-cbc':
            case 'aes128-cbc':
                $this->encrypt = new Crypt_AES();
                $this->encrypt_block_size = 16; // eg. 128 / 8
                break;
            case 'aes256-ctr':
            case 'aes192-ctr':
            case 'aes128-ctr':
                $this->encrypt = new Crypt_AES(Crypt_AES::MODE_CTR);
                $this->encrypt_block_size = 16; // eg. 128 / 8
                break;
            case 'arcfour':
            case 'arcfour128':
            case 'arcfour256':
                $this->encrypt = new Crypt_RC4();
                break;
            case 'none';
                //$this->encrypt = new Crypt_Null();
        }

        switch ($decrypt) {
            case '3des-cbc':
                $this->decrypt = new Crypt_TripleDES();
                break;
            case '3des-ctr':
                $this->decrypt = new Crypt_TripleDES(Crypt_DES::MODE_CTR);
                break;
            case 'aes256-cbc':
            case 'aes192-cbc':
            case 'aes128-cbc':
                $this->decrypt = new Crypt_AES();
                $this->decrypt_block_size = 16;
                break;
            case 'aes256-ctr':
            case 'aes192-ctr':
            case 'aes128-ctr':
                $this->decrypt = new Crypt_AES(Crypt_AES::MODE_CTR);
                $this->decrypt_block_size = 16;
                break;
            case 'arcfour':
            case 'arcfour128':
            case 'arcfour256':
                $this->decrypt = new Crypt_RC4();
                break;
            case 'none';
                //$this->decrypt = new Crypt_Null();
        }

        $keyBytes = pack('Na*', strlen($keyBytes), $keyBytes);

        if ($this->encrypt) {
            $this->encrypt->enableContinuousBuffer();
            $this->encrypt->disablePadding();

            $iv = pack('H*', $hash($keyBytes . $this->exchange_hash . 'A' . $this->session_id));
            while ($this->encrypt_block_size > strlen($iv)) {
                $iv.= pack('H*', $hash($keyBytes . $this->exchange_hash . $iv));
            }
            $this->encrypt->setIV(substr($iv, 0, $this->encrypt_block_size));

            $key = pack('H*', $hash($keyBytes . $this->exchange_hash . 'C' . $this->session_id));
            while ($encryptKeyLength > strlen($key)) {
                $key.= pack('H*', $hash($keyBytes . $this->exchange_hash . $key));
            }
            $this->encrypt->setKey(substr($key, 0, $encryptKeyLength));
        }

        if ($this->decrypt) {
            $this->decrypt->enableContinuousBuffer();
            $this->decrypt->disablePadding();

            $iv = pack('H*', $hash($keyBytes . $this->exchange_hash . 'B' . $this->session_id));
            while ($this->decrypt_block_size > strlen($iv)) {
                $iv.= pack('H*', $hash($keyBytes . $this->exchange_hash . $iv));
            }
            $this->decrypt->setIV(substr($iv, 0, $this->decrypt_block_size));

            $key = pack('H*', $hash($keyBytes . $this->exchange_hash . 'D' . $this->session_id));
            while ($decryptKeyLength > strlen($key)) {
                $key.= pack('H*', $hash($keyBytes . $this->exchange_hash . $key));
            }
            $this->decrypt->setKey(substr($key, 0, $decryptKeyLength));
        }

        /* The "arcfour128" algorithm is the RC4 cipher, as described in
           [SCHNEIER], using a 128-bit key.  The first 1536 bytes of keystream
           generated by the cipher MUST be discarded, and the first byte of the
           first encrypted packet MUST be encrypted using the 1537th byte of
           keystream.

           -- http://tools.ietf.org/html/rfc4345#section-4 */
        if ($encrypt == 'arcfour128' || $encrypt == 'arcfour256') {
            $this->encrypt->encrypt(str_repeat("\0", 1536));
        }
        if ($decrypt == 'arcfour128' || $decrypt == 'arcfour256') {
            $this->decrypt->decrypt(str_repeat("\0", 1536));
        }

        for ($i = 0; $i < count($mac_algorithms) && !in_array($mac_algorithms[$i], $this->mac_algorithms_client_to_server); $i++);
        if ($i == count($mac_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible client to server message authentication algorithms found', E_USER_NOTICE);
        }

        $createKeyLength = 0; // ie. $mac_algorithms[$i] == 'none'
        switch ($mac_algorithms[$i]) {
            case 'hmac-sha1':
                $this->hmac_create = new Crypt_Hash('sha1');
                $createKeyLength = 20;
                break;
            case 'hmac-sha1-96':
                $this->hmac_create = new Crypt_Hash('sha1-96');
                $createKeyLength = 20;
                break;
            case 'hmac-md5':
                $this->hmac_create = new Crypt_Hash('md5');
                $createKeyLength = 16;
                break;
            case 'hmac-md5-96':
                $this->hmac_create = new Crypt_Hash('md5-96');
                $createKeyLength = 16;
        }

        for ($i = 0; $i < count($mac_algorithms) && !in_array($mac_algorithms[$i], $this->mac_algorithms_server_to_client); $i++);
        if ($i == count($mac_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible server to client message authentication algorithms found', E_USER_NOTICE);
        }

        $checkKeyLength = 0;
        $this->hmac_size = 0;
        switch ($mac_algorithms[$i]) {
            case 'hmac-sha1':
                $this->hmac_check = new Crypt_Hash('sha1');
                $checkKeyLength = 20;
                $this->hmac_size = 20;
                break;
            case 'hmac-sha1-96':
                $this->hmac_check = new Crypt_Hash('sha1-96');
                $checkKeyLength = 20;
                $this->hmac_size = 12;
                break;
            case 'hmac-md5':
                $this->hmac_check = new Crypt_Hash('md5');
                $checkKeyLength = 16;
                $this->hmac_size = 16;
                break;
            case 'hmac-md5-96':
                $this->hmac_check = new Crypt_Hash('md5-96');
                $checkKeyLength = 16;
                $this->hmac_size = 12;
        }

        $key = pack('H*', $hash($keyBytes . $this->exchange_hash . 'E' . $this->session_id));
        while ($createKeyLength > strlen($key)) {
            $key.= pack('H*', $hash($keyBytes . $this->exchange_hash . $key));
        }
        $this->hmac_create->setKey(substr($key, 0, $createKeyLength));

        $key = pack('H*', $hash($keyBytes . $this->exchange_hash . 'F' . $this->session_id));
        while ($checkKeyLength > strlen($key)) {
            $key.= pack('H*', $hash($keyBytes . $this->exchange_hash . $key));
        }
        $this->hmac_check->setKey(substr($key, 0, $checkKeyLength));

        for ($i = 0; $i < count($compression_algorithms) && !in_array($compression_algorithms[$i], $this->compression_algorithms_server_to_client); $i++);
        if ($i == count($compression_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible server to client compression algorithms found', E_USER_NOTICE);
        }
        $this->decompress = $compression_algorithms[$i] == 'zlib';

        for ($i = 0; $i < count($compression_algorithms) && !in_array($compression_algorithms[$i], $this->compression_algorithms_client_to_server); $i++);
        if ($i == count($compression_algorithms)) {
            $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
            throw new \Exception('No compatible client to server compression algorithms found', E_USER_NOTICE);
        }
        $this->compress = $compression_algorithms[$i] == 'zlib';

        return true;
    }

    /**
     * Login
     *
     * The $password parameter can be a plaintext password or a Crypt_RSA object.
     *
     * @param String $username
     * @param optional String $password
     * @return Boolean
     * @access public
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    function login($username, $password = '')
    {
        if (!($this->bitmap & self::MASK_CONSTRUCTOR)) {
            return false;
        }

        $packet = pack('CNa*',
            self::MSG_SERVICE_REQUEST, strlen('ssh-userauth'), 'ssh-userauth'
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        if ($type != self::MSG_SERVICE_ACCEPT) {
            throw new \Exception('Expected SSH_MSG_SERVICE_ACCEPT', E_USER_NOTICE);
        }

        if (is_object($password)) {
            if ($password instanceof Crypt_RSA) {
                return $this->_privatekey_login($username, $password);
            }
            if ($password instanceof File_Agent) {
                return $this->_ssh_agent_login($username, $password);
            }
        }

        $packet = pack('CNa*Na*Na*CNa*',
            self::MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
            strlen('password'), 'password', 0, strlen($password), $password
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        // remove the username and password from the last logged packet
        if (self::$logging && self::$logging == self::LOG_COMPLEX) {
            $packet = pack('CNa*Na*Na*CNa*',
                self::MSG_USERAUTH_REQUEST, strlen('username'), 'username', strlen('ssh-connection'), 'ssh-connection',
                strlen('password'), 'password', 0, strlen('password'), 'password'
            );
            $this->message_log[count($this->message_log) - 1] = $packet;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case self::MSG_USERAUTH_PASSWD_CHANGEREQ: // in theory, the password can be changed
                if (self::$logging) {
                    $this->message_number_log[count($this->message_number_log) - 1] = 'Net_SSH2::MSG_USERAUTH_PASSWD_CHANGEREQ';
                }
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->errors[] = 'SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: ' . utf8_decode($this->_string_shift($response, $length));
                return $this->_disconnect(self::DISCONNECT_AUTH_CANCELLED_BY_USER);
            case self::MSG_USERAUTH_FAILURE:
                // can we use keyboard-interactive authentication?  if not then either the login is bad or the server employees
                // multi-factor authentication
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $auth_methods = explode(',', $this->_string_shift($response, $length));
                if (in_array('keyboard-interactive', $auth_methods)) {
                    if ($this->_keyboard_interactive_login($username, $password)) {
                        $this->bitmap |= self::MASK_LOGIN;
                        return true;
                    }
                    return false;
                }
                return false;
            case self::MSG_USERAUTH_SUCCESS:
                $this->bitmap |= self::MASK_LOGIN;
                return true;
        }

        return false;
    }

    /**
     * Login with ssh-agent
     *
     * Try to login with all the key added to ssh-agent
     *
     * @param String $username
     * @return Boolean
     * @access private
     */
    function _ssh_agent_login($username, $agent)
    {
        $this->agent = $agent;

        $this->agent->connect();
        $this->agent->requestIdentities();

        foreach ($agent->getKeys() as $key) {
            if ($this->_privatekey_login($username, $key, self::PRIVKEY_MODE_AGENT)) {
                return true;
            }
        }

        $this->_disconnect(self::DISCONNECT_AUTH_CANCELLED_BY_USER);

        return false;
    }

    /**
     * Login via keyboard-interactive authentication
     *
     * See {@link http://tools.ietf.org/html/rfc4256 RFC4256} for details.  This is not a full-featured keyboard-interactive authenticator.
     *
     * @param String $username
     * @param String $password
     * @return Boolean
     * @access private
     */
    function _keyboard_interactive_login($username, $password)
    {
        $packet = pack('CNa*Na*Na*Na*Na*',
            self::MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
            strlen('keyboard-interactive'), 'keyboard-interactive', 0, '', 0, ''
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        return $this->_keyboard_interactive_process($password);
    }

    /**
     * Handle the keyboard-interactive requests / responses.
     *
     * @param String $responses...
     * @return Boolean
     * @access private
     */
    function _keyboard_interactive_process()
    {
        $responses = func_get_args();

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case self::MSG_USERAUTH_INFO_REQUEST:
                // see http://tools.ietf.org/html/rfc4256#section-3.2
                if (self::$logging) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'self::MSG_USERAUTH_INFO_REQUEST',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                }

                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->_string_shift($response, $length); // name; may be empty
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->_string_shift($response, $length); // instruction; may be empty
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->_string_shift($response, $length); // language tag; may be empty
                extract(unpack('Nnum_prompts', $this->_string_shift($response, 4)));
                /*
                for ($i = 0; $i < $num_prompts; $i++) {
                    extract(unpack('Nlength', $this->_string_shift($response, 4)));
                    // prompt - ie. "Password: "; must not be empty
                    $this->_string_shift($response, $length);
                    $echo = $this->_string_shift($response) != chr(0);
                }
                */

                /*
                   After obtaining the requested information from the user, the client
                   MUST respond with an SSH_MSG_USERAUTH_INFO_RESPONSE message.
                */
                // see http://tools.ietf.org/html/rfc4256#section-3.4
                $packet = $logged = pack('CN', self::MSG_USERAUTH_INFO_RESPONSE, count($responses));
                for ($i = 0; $i < count($responses); $i++) {
                    $packet.= pack('Na*', strlen($responses[$i]), $responses[$i]);
                    $logged.= pack('Na*', strlen('dummy-answer'), 'dummy-answer');
                }

                if (!$this->_send_binary_packet($packet)) {
                    return false;
                }

                if (self::$logging) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'self::MSG_USERAUTH_INFO_RESPONSE',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                    $this->message_log[count($this->message_log) - 1] = $logged;
                }

                /*
                   After receiving the response, the server MUST send either an
                   SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, or another
                   SSH_MSG_USERAUTH_INFO_REQUEST message.
                */
                // maybe phpseclib should force close the connection after x request / responses?  unless something like that is done
                // there could be an infinite loop of request / responses.
                return $this->_keyboard_interactive_process();
            case self::MSG_USERAUTH_SUCCESS:
                return true;
            case self::MSG_USERAUTH_FAILURE:
                return false;
        }

        return false;
    }

    /**
     * Login with an RSA private key
     *
     * @param String $username
     * @param Crypt_RSA $password
     * @return Boolean
     * @access private
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    function _privatekey_login($username, $privatekey, $mode = self::PRIVKEY_MODE_RSA)
    {
        // see http://tools.ietf.org/html/rfc4253#page-15
        $publickey = $privatekey->getPublicKey(Crypt_RSA::PUBLIC_FORMAT_RAW);
        if ($publickey === false) {
            return false;
        }

        $publickey = array(
            'e' => $publickey['e']->toBytes(true),
            'n' => $publickey['n']->toBytes(true)
        );
        $publickey = pack('Na*Na*Na*',
            strlen('ssh-rsa'), 'ssh-rsa', strlen($publickey['e']), $publickey['e'], strlen($publickey['n']), $publickey['n']
        );

        $part1 = pack('CNa*Na*Na*',
            self::MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
            strlen('publickey'), 'publickey'
        );
        $part2 = pack('Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publickey), $publickey);

        $packet = $part1 . chr(0) . $part2;
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case self::MSG_USERAUTH_FAILURE:
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->errors[] = 'SSH_MSG_USERAUTH_FAILURE: ' . $this->_string_shift($response, $length);
                return $mode == self::PRIVKEY_MODE_AGENT ? false : $this->_disconnect(self::DISCONNECT_AUTH_CANCELLED_BY_USER);
            case self::MSG_USERAUTH_PK_OK:
                // we'll just take it on faith that the public key blob and the public key algorithm name are as
                // they should be
                if (self::$logging) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'self::MSG_USERAUTH_PK_OK',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                }
        }

        $packet = $part1 . chr(1) . $part2;
        $data = pack('Na*a*', strlen($this->session_id), $this->session_id, $packet);

        switch ($mode) {
            case self::PRIVKEY_MODE_AGENT:
                $signature = $this->agent->sign($publickey, $data);
                break;
            //case self::PRIVKEY_MODE_RSA:
            default:
                $privatekey->setSignatureMode(Crypt_RSA::SIGNATURE_PKCS1);
                $signature = $privatekey->sign($data);
                $signature = pack('Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($signature), $signature);
        }

        $packet.= pack('Na*', strlen($signature), $signature);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case self::MSG_USERAUTH_FAILURE:
                // either the login is bad or the server employs multi-factor authentication
                return false;
            case self::MSG_USERAUTH_SUCCESS:
                $this->bitmap |= self::MASK_LOGIN;
                return true;
        }

        return false;
    }

    /**
     * Set logging mode. Defaults to Net_SSH2::LOG_SIMPLE
     * 
     * @see $logging
     */
    static function setLogging($logging = self::LOG_SIMPLE){
        self::$logging = $logging;
    }

    /**
     * Set Timeout
     *
     * $ssh->exec('ping 127.0.0.1'); on a Linux host will never return and will run indefinitely.  setTimeout() makes it so it'll timeout.
     * Setting $timeout to false or 0 will mean there is no timeout.
     *
     * @param Mixed $timeout
     */
    function setTimeout($timeout)
    {
        $this->timeout = $this->curTimeout = $timeout;
    }

    /**
     * Execute Command
     *
     * If $block is set to false then Net_SSH2::_get_channel_packet(self::CHANNEL_EXEC) will need to be called manually.
     * In all likelihood, this is not a feature you want to be taking advantage of.
     *
     * @param String $command
     * @param optional Boolean $block
     * @return String
     * @access public
     */
    function exec($command, $block = true)
    {
        $this->curTimeout = $this->timeout;

        if (!($this->bitmap & self::MASK_LOGIN)) {
            return false;
        }

        // RFC4254 defines the (client) window size as "bytes the other party can send before it must wait for the window to
        // be adjusted".  0x7FFFFFFF is, at 4GB, the max size.  technically, it should probably be decremented, but,
        // honestly, if you're transfering more than 4GB, you probably shouldn't be using phpseclib, anyway.
        // see http://tools.ietf.org/html/rfc4254#section-5.2 for more info
        $this->window_size_client_to_server[self::CHANNEL_EXEC] = 0x7FFFFFFF;
        // 0x8000 is the maximum max packet size, per http://tools.ietf.org/html/rfc4253#section-6.1, although since PuTTy
        // uses 0x4000, that's what will be used here, as well.
        $packet_size = 0x4000;

        $packet = pack('CNa*N3',
            self::MSG_CHANNEL_OPEN, strlen('session'), 'session', self::CHANNEL_EXEC, $this->window_size_client_to_server[self::CHANNEL_EXEC], $packet_size);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_EXEC] = self::MSG_CHANNEL_OPEN;

        $response = $this->_get_channel_packet(self::CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        // sending a pty-req SSH_MSG_CHANNEL_REQUEST message is unnecessary and, in fact, in most cases, slows things
        // down.  the one place where it might be desirable is if you're doing something like Net_SSH2::exec('ping localhost &').
        // with a pty-req SSH_MSG_CHANNEL_REQUEST, exec() will return immediately and the ping process will then
        // then immediately terminate.  without such a request exec() will loop indefinitely.  the ping process won't end but
        // neither will your script.

        // although, in theory, the size of SSH_MSG_CHANNEL_REQUEST could exceed the maximum packet size established by
        // SSH_MSG_CHANNEL_OPEN_CONFIRMATION, RFC4254#section-5.1 states that the "maximum packet size" refers to the
        // "maximum size of an individual data packet". ie. SSH_MSG_CHANNEL_DATA.  RFC4254#section-5.2 corroborates.
        $packet = pack('CNNa*CNa*',
            self::MSG_CHANNEL_REQUEST, $this->server_channels[self::CHANNEL_EXEC], strlen('exec'), 'exec', 1, strlen($command), $command);
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_EXEC] = self::MSG_CHANNEL_REQUEST;

        $response = $this->_get_channel_packet(self::CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        $this->channel_status[self::CHANNEL_EXEC] = self::MSG_CHANNEL_DATA;

        if (!$block) {
            return true;
        }

        $output = '';
        while (true) {
            $temp = $this->_get_channel_packet(self::CHANNEL_EXEC);
            switch (true) {
                case $temp === true:
                    return $output;
                case $temp === false:
                    return false;
                default:
                    $output.= $temp;
            }
        }
    }

    /**
     * Creates an interactive shell
     *
     * @see Net_SSH2::read()
     * @see Net_SSH2::write()
     * @return Boolean
     * @access private
     */
    function _initShell()
    {
        $this->window_size_client_to_server[self::CHANNEL_SHELL] = 0x7FFFFFFF;
        $packet_size = 0x4000;

        $packet = pack('CNa*N3',
            self::MSG_CHANNEL_OPEN, strlen('session'), 'session', self::CHANNEL_SHELL, $this->window_size_client_to_server[self::CHANNEL_SHELL], $packet_size);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_SHELL] = self::MSG_CHANNEL_OPEN;

        $response = $this->_get_channel_packet(self::CHANNEL_SHELL);
        if ($response === false) {
            return false;
        }

        $terminal_modes = pack('C', self::TTY_OP_END);
        $packet = pack('CNNa*CNa*N5a*',
            self::MSG_CHANNEL_REQUEST, $this->server_channels[self::CHANNEL_SHELL], strlen('pty-req'), 'pty-req', 1, strlen('vt100'), 'vt100',
            80, 24, 0, 0, strlen($terminal_modes), $terminal_modes);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            throw new \Exception('Connection closed by server', E_USER_NOTICE);
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        switch ($type) {
            case self::MSG_CHANNEL_SUCCESS:
                break;
            case self::MSG_CHANNEL_FAILURE:
            default:
                $this->_disconnect(self::DISCONNECT_BY_APPLICATION);
                throw new \Exception('Unable to request pseudo-terminal', E_USER_NOTICE);
        }

        $packet = pack('CNNa*C',
            self::MSG_CHANNEL_REQUEST, $this->server_channels[self::CHANNEL_SHELL], strlen('shell'), 'shell', 1);
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_SHELL] = self::MSG_CHANNEL_REQUEST;

        $response = $this->_get_channel_packet(self::CHANNEL_SHELL);
        if ($response === false) {
            return false;
        }

        $this->channel_status[self::CHANNEL_SHELL] = self::MSG_CHANNEL_DATA;

        $this->bitmap |= self::MASK_SHELL;

        return true;
    }

    /**
     * Returns the output of an interactive shell
     *
     * Returns when there's a match for $expect, which can take the form of a string literal or,
     * if $mode == self::READ_REGEX, a regular expression.
     *
     * @see Net_SSH2::read()
     * @param String $expect
     * @param Integer $mode
     * @return String
     * @access public
     */
    function read($expect = '', $mode = self::READ_SIMPLE)
    {
        $this->curTimeout = $this->timeout;

        if (!($this->bitmap & self::MASK_LOGIN)) {
            throw new \Exception('Operation disallowed prior to login()', E_USER_NOTICE);
        }

        if (!($this->bitmap & self::MASK_SHELL) && !$this->_initShell()) {
            throw new \Exception('Unable to initiate an interactive shell session', E_USER_NOTICE);
        }

        $match = $expect;
        while (true) {
            if ($mode == self::READ_REGEX) {
                preg_match($expect, $this->interactiveBuffer, $matches);
                $match = $matches[0];
            }
            $pos = !empty($match) ? strpos($this->interactiveBuffer, $match) : false;
            if ($pos !== false) {
                return $this->_string_shift($this->interactiveBuffer, $pos + strlen($match));
            }
            $response = $this->_get_channel_packet(self::CHANNEL_SHELL);
            if (is_bool($response)) {
                return $response ? $this->_string_shift($this->interactiveBuffer, strlen($this->interactiveBuffer)) : false;
            }

            $this->interactiveBuffer.= $response;
        }
    }

    /**
     * Inputs a command into an interactive shell.
     *
     * @see Net_SSH1::interactiveWrite()
     * @param String $cmd
     * @return Boolean
     * @access public
     */
    function write($cmd)
    {
        if (!($this->bitmap & self::MASK_LOGIN)) {
            throw new \Exception('Operation disallowed prior to login()', E_USER_NOTICE);
        }

        if (!($this->bitmap & self::MASK_SHELL) && !$this->_initShell()) {
            throw new \Exception('Unable to initiate an interactive shell session', E_USER_NOTICE);
        }

        return $this->_send_channel_packet(self::CHANNEL_SHELL, $cmd);
    }

    /**
     * Disconnect
     *
     * @access public
     */
    function disconnect()
    {
        $this->_disconnect(self::DISCONNECT_BY_APPLICATION);
        if (isset($this->realtime_log_file) && is_resource($this->realtime_log_file)) {
            fclose($this->realtime_log_file);
        }
    }

    /**
     * Destructor.
     *
     * Will be called, automatically, if you're supporting just PHP5.  If you're supporting PHP4, you'll need to call
     * disconnect().
     *
     * @access public
     */
    function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Gets Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @see Net_SSH2::_send_binary_packet()
     * @return String
     * @access private
     */
    function _get_binary_packet()
    {
        if (!is_resource($this->fsock) || feof($this->fsock)) {
            throw new \Exception('Connection closed prematurely', E_USER_NOTICE);
        }

        $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
        $raw = fread($this->fsock, $this->decrypt_block_size);
        $stop = strtok(microtime(), ' ') + strtok('');

        if (empty($raw)) {
            return '';
        }

        if ($this->decrypt !== false) {
            $raw = $this->decrypt->decrypt($raw);
        }
        if ($raw === false) {
            throw new \Exception('Unable to decrypt content', E_USER_NOTICE);
        }

        extract(unpack('Npacket_length/Cpadding_length', $this->_string_shift($raw, 5)));

        $remaining_length = $packet_length + 4 - $this->decrypt_block_size;
        $buffer = '';
        while ($remaining_length > 0) {
            $temp = fread($this->fsock, $remaining_length);
            $buffer.= $temp;
            $remaining_length-= strlen($temp);
        }
        if (!empty($buffer)) {
            $raw.= $this->decrypt !== false ? $this->decrypt->decrypt($buffer) : $buffer;
            $buffer = $temp = '';
        }

        $payload = $this->_string_shift($raw, $packet_length - $padding_length - 1);
        $padding = $this->_string_shift($raw, $padding_length); // should leave $raw empty

        if ($this->hmac_check !== false) {
            $hmac = fread($this->fsock, $this->hmac_size);
            if ($hmac != $this->hmac_check->hash(pack('NNCa*', $this->get_seq_no, $packet_length, $padding_length, $payload . $padding))) {
                throw new \Exception('Invalid HMAC', E_USER_NOTICE);
            }
        }

        //if ($this->decompress) {
        //    $payload = gzinflate(substr($payload, 2));
        //}

        $this->get_seq_no++;

        if (self::$logging) {
            $message_number = isset($this->message_numbers[ord($payload[0])]) ? $this->message_numbers[ord($payload[0])] : 'UNKNOWN (' . ord($payload[0]) . ')';
            $message_number = '<- ' . $message_number .
                              ' (' . round($stop - $start, 4) . 's)';
            $this->_append_log($message_number, $payload);
        }

        return $this->_filter($payload);
    }

    /**
     * Filter Binary Packets
     *
     * Because some binary packets need to be ignored...
     *
     * @see Net_SSH2::_get_binary_packet()
     * @return String
     * @access private
     */
    function _filter($payload)
    {
        switch (ord($payload[0])) {
            case self::MSG_DISCONNECT:
                $this->_string_shift($payload, 1);
                extract(unpack('Nreason_code/Nlength', $this->_string_shift($payload, 8)));
                $this->errors[] = 'SSH_MSG_DISCONNECT: ' . $this->disconnect_reasons[$reason_code] . "\r\n" . utf8_decode($this->_string_shift($payload, $length));
                $this->bitmask = 0;
                return false;
            case self::MSG_IGNORE:
                $payload = $this->_get_binary_packet();
                break;
            case self::MSG_DEBUG:
                $this->_string_shift($payload, 2);
                extract(unpack('Nlength', $this->_string_shift($payload, 4)));
                $this->errors[] = 'SSH_MSG_DEBUG: ' . utf8_decode($this->_string_shift($payload, $length));
                $payload = $this->_get_binary_packet();
                break;
            case self::MSG_UNIMPLEMENTED:
                return false;
            case self::MSG_KEXINIT:
                if ($this->session_id !== false) {
                    if (!$this->_key_exchange($payload)) {
                        $this->bitmask = 0;
                        return false;
                    }
                    $payload = $this->_get_binary_packet();
                }
        }

        // see http://tools.ietf.org/html/rfc4252#section-5.4; only called when the encryption has been activated and when we haven't already logged in
        if (($this->bitmap & self::MASK_CONSTRUCTOR) && !($this->bitmap & self::MASK_LOGIN) && ord($payload[0]) == self::MSG_USERAUTH_BANNER) {
            $this->_string_shift($payload, 1);
            extract(unpack('Nlength', $this->_string_shift($payload, 4)));
            $this->errors[] = 'SSH_MSG_USERAUTH_BANNER: ' . utf8_decode($this->_string_shift($payload, $length));
            $payload = $this->_get_binary_packet();
        }

        // only called when we've already logged in
        if (($this->bitmap & self::MASK_CONSTRUCTOR) && ($this->bitmap & self::MASK_LOGIN)) {
            switch (ord($payload[0])) {
                case self::MSG_GLOBAL_REQUEST: // see http://tools.ietf.org/html/rfc4254#section-4
                    $this->_string_shift($payload, 1);
                    extract(unpack('Nlength', $this->_string_shift($payload)));
                    $this->errors[] = 'SSH_MSG_GLOBAL_REQUEST: ' . utf8_decode($this->_string_shift($payload, $length));

                    if (!$this->_send_binary_packet(pack('C', self::MSG_REQUEST_FAILURE))) {
                        return $this->_disconnect(self::DISCONNECT_BY_APPLICATION);
                    }

                    $payload = $this->_get_binary_packet();
                    break;
                case self::MSG_CHANNEL_OPEN: // see http://tools.ietf.org/html/rfc4254#section-5.1
                    $this->_string_shift($payload, 1);
                    extract(unpack('N', $this->_string_shift($payload, 4)));
                    $this->errors[] = 'SSH_MSG_CHANNEL_OPEN: ' . utf8_decode($this->_string_shift($payload, $length));

                    $this->_string_shift($payload, 4); // skip over client channel
                    extract(unpack('Nserver_channel', $this->_string_shift($payload, 4)));

                    $packet = pack('CN3a*Na*',
                        self::MSG_REQUEST_FAILURE, $server_channel, self::OPEN_ADMINISTRATIVELY_PROHIBITED, 0, '', 0, '');

                    if (!$this->_send_binary_packet($packet)) {
                        return $this->_disconnect(self::DISCONNECT_BY_APPLICATION);
                    }

                    $payload = $this->_get_binary_packet();
                    break;
                case self::MSG_CHANNEL_WINDOW_ADJUST:
                    $payload = $this->_get_binary_packet();
            }
        }

        return $payload;
    }

    /**
     * Enable Quiet Mode
     *
     * Suppress stderr from output
     *
     * @access public
     */
    function enableQuietMode()
    {
        $this->quiet_mode = true;
    }

    /**
     * Disable Quiet Mode
     *
     * Show stderr in output
     *
     * @access public
     */
    function disableQuietMode()
    {
        $this->quiet_mode = false;
    }

    /**
     * Gets channel data
     *
     * Returns the data as a string if it's available and false if not.
     *
     * @param $client_channel
     * @return Mixed
     * @access private
     */
    function _get_channel_packet($client_channel, $skip_extended = false)
    {
        if (!empty($this->channel_buffers[$client_channel])) {
            return array_shift($this->channel_buffers[$client_channel]);
        }

        while (true) {
            if ($this->curTimeout) {
                $read = array($this->fsock);
                $write = $except = NULL;

                $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
                $sec = floor($this->curTimeout);
                $usec = 1000000 * ($this->curTimeout - $sec);
                // on windows this returns a "Warning: Invalid CRT parameters detected" error
                if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
                    $this->_close_channel($client_channel);
                    return true;
                }
                $elapsed = strtok(microtime(), ' ') + strtok('') - $start;
                $this->curTimeout-= $elapsed;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                throw new \Exception('Connection closed by server', E_USER_NOTICE);
            }

            if (empty($response)) {
                return '';
            }

            extract(unpack('Ctype/Nchannel', $this->_string_shift($response, 5)));

            switch ($this->channel_status[$channel]) {
                case self::MSG_CHANNEL_OPEN:
                    switch ($type) {
                        case self::MSG_CHANNEL_OPEN_CONFIRMATION:
                            extract(unpack('Nserver_channel', $this->_string_shift($response, 4)));
                            $this->server_channels[$channel] = $server_channel;
                            $this->_string_shift($response, 4); // skip over (server) window size
                            $temp = unpack('Npacket_size_client_to_server', $this->_string_shift($response, 4));
                            $this->packet_size_client_to_server[$channel] = $temp['packet_size_client_to_server'];
                            return $client_channel == $channel ? true : $this->_get_channel_packet($client_channel, $skip_extended);
                        //case self::MSG_CHANNEL_OPEN_FAILURE:
                        default:
                            $this->_disconnect(self::DISCONNECT_BY_APPLICATION);
                            throw new \Exception('Unable to open channel', E_USER_NOTICE);
                    }
                    break;
                case self::MSG_CHANNEL_REQUEST:
                    switch ($type) {
                        case self::MSG_CHANNEL_SUCCESS:
                            return true;
                        //case self::MSG_CHANNEL_FAILURE:
                        default:
                            $this->_disconnect(self::DISCONNECT_BY_APPLICATION);
                            throw new \Exception('Unable to request pseudo-terminal', E_USER_NOTICE);
                    }
                case self::MSG_CHANNEL_CLOSE:
                    return $type == self::MSG_CHANNEL_CLOSE ? true : $this->_get_channel_packet($client_channel, $skip_extended);
            }

            switch ($type) {
                case self::MSG_CHANNEL_DATA:
                    /*
                    if ($client_channel == self::CHANNEL_EXEC) {
                        // SCP requires null packets, such as this, be sent.  further, in the case of the ssh.com SSH server
                        // this actually seems to make things twice as fast.  more to the point, the message right after
                        // SSH_MSG_CHANNEL_DATA (usually SSH_MSG_IGNORE) won't block for as long as it would have otherwise.
                        // in OpenSSH it slows things down but only by a couple thousandths of a second.
                        $this->_send_channel_packet($client_channel, chr(0));
                    }
                    */
                    extract(unpack('Nlength', $this->_string_shift($response, 4)));
                    $data = $this->_string_shift($response, $length);
                    if ($client_channel == $channel) {
                        return $data;
                    }
                    if (!isset($this->channel_buffers[$client_channel])) {
                        $this->channel_buffers[$client_channel] = array();
                    }
                    $this->channel_buffers[$client_channel][] = $data;
                    break;
                case self::MSG_CHANNEL_EXTENDED_DATA:
                    if ($skip_extended || $this->quiet_mode) {
                        break;
                    }
                    /*
                    if ($client_channel == self::CHANNEL_EXEC) {
                        $this->_send_channel_packet($client_channel, chr(0));
                    }
                    */
                    // currently, there's only one possible value for $data_type_code: self::EXTENDED_DATA_STDERR
                    extract(unpack('Ndata_type_code/Nlength', $this->_string_shift($response, 8)));
                    $data = $this->_string_shift($response, $length);
                    if ($client_channel == $channel) {
                        return $data;
                    }
                    if (!isset($this->channel_buffers[$client_channel])) {
                        $this->channel_buffers[$client_channel] = array();
                    }
                    $this->channel_buffers[$client_channel][] = $data;
                    break;
                case self::MSG_CHANNEL_REQUEST:
                    extract(unpack('Nlength', $this->_string_shift($response, 4)));
                    $value = $this->_string_shift($response, $length);
                    switch ($value) {
                        case 'exit-signal':
                            $this->_string_shift($response, 1);
                            extract(unpack('Nlength', $this->_string_shift($response, 4)));
                            $this->errors[] = 'SSH_MSG_CHANNEL_REQUEST (exit-signal): ' . $this->_string_shift($response, $length);
                            $this->_string_shift($response, 1);
                            extract(unpack('Nlength', $this->_string_shift($response, 4)));
                            if ($length) {
                                $this->errors[count($this->errors)].= "\r\n" . $this->_string_shift($response, $length);
                            }
                        case 'exit-status':
                            // "The channel needs to be closed with SSH_MSG_CHANNEL_CLOSE after this message."
                            // -- http://tools.ietf.org/html/rfc4254#section-6.10
                            $this->_send_binary_packet(pack('CN', self::MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));
                            $this->_send_binary_packet(pack('CN', self::MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));

                            $this->channel_status[$channel] = self::MSG_CHANNEL_EOF;
                        default:
                            // "Some systems may not implement signals, in which case they SHOULD ignore this message."
                            //  -- http://tools.ietf.org/html/rfc4254#section-6.9
                            break;
                    }
                    break;
                case self::MSG_CHANNEL_CLOSE:
                    $this->curTimeout = 0;

                    if ($this->bitmap & self::MASK_SHELL) {
                        $this->bitmap&= ~self::MASK_SHELL;
                    }
                    if ($this->channel_status[$channel] != self::MSG_CHANNEL_EOF) {
                        $this->_send_binary_packet(pack('CN', self::MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));
                    }

                    $this->channel_status[$channel] = self::MSG_CHANNEL_CLOSE;
                    return true;
                case self::MSG_CHANNEL_EOF:
                    break;
                default:
                    $this->_disconnect(self::DISCONNECT_BY_APPLICATION);
                    throw new \Exception('Error reading channel data', E_USER_NOTICE);
            }
        }
    }

    /**
     * Sends Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @param String $data
     * @see Net_SSH2::_get_binary_packet()
     * @return Boolean
     * @access private
     */
    function _send_binary_packet($data)
    {
        if (!is_resource($this->fsock) || feof($this->fsock)) {
            throw new \Exception('Connection closed prematurely', E_USER_NOTICE);
        }

        //if ($this->compress) {
        //    // the -4 removes the checksum:
        //    // http://php.net/function.gzcompress#57710
        //    $data = substr(gzcompress($data), 0, -4);
        //}

        // 4 (packet length) + 1 (padding length) + 4 (minimal padding amount) == 9
        $packet_length = strlen($data) + 9;
        // round up to the nearest $this->encrypt_block_size
        $packet_length+= (($this->encrypt_block_size - 1) * $packet_length) % $this->encrypt_block_size;
        // subtracting strlen($data) is obvious - subtracting 5 is necessary because of packet_length and padding_length
        $padding_length = $packet_length - strlen($data) - 5;

        $padding = '';
        for ($i = 0; $i < $padding_length; $i++) {
            $padding.= chr(Crypt_Random::generateRandom(0, 255));
        }

        // we subtract 4 from packet_length because the packet_length field isn't supposed to include itself
        $packet = pack('NCa*', $packet_length - 4, $padding_length, $data . $padding);

        $hmac = $this->hmac_create !== false ? $this->hmac_create->hash(pack('Na*', $this->send_seq_no, $packet)) : '';
        $this->send_seq_no++;

        if ($this->encrypt !== false) {
            $packet = $this->encrypt->encrypt($packet);
        }

        $packet.= $hmac;

        $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
        $result = strlen($packet) == fputs($this->fsock, $packet);
        $stop = strtok(microtime(), ' ') + strtok('');

        if (self::$logging) {
            $message_number = isset($this->message_numbers[ord($data[0])]) ? $this->message_numbers[ord($data[0])] : 'UNKNOWN (' . ord($data[0]) . ')';
            $message_number = '-> ' . $message_number .
                              ' (' . round($stop - $start, 4) . 's)';
            $this->_append_log($message_number, $data);
        }

        return $result;
    }

    /**
     * Logs data packets
     *
     * Makes sure that only the last 1MB worth of packets will be logged
     *
     * @param String $data
     * @access private
     */
    function _append_log($message_number, $message)
    {
            switch (self::$logging) {
                // useful for benchmarks
                case self::LOG_SIMPLE:
                    $this->message_number_log[] = $message_number;
                    break;
                // the most useful log for SSH2
                case self::LOG_COMPLEX:
                    $this->message_number_log[] = $message_number;
                    $this->_string_shift($message);
                    $this->log_size+= strlen($message);
                    $this->message_log[] = $message;
                    while ($this->log_size > self::LOG_MAX_SIZE) {
                        $this->log_size-= strlen(array_shift($this->message_log));
                        array_shift($this->message_number_log);
                    }
                    break;
                // dump the output out realtime; packets may be interspersed with non packets,
                // passwords won't be filtered out and select other packets may not be correctly
                // identified
                case self::LOG_REALTIME:
                    echo "<pre>\r\n" . $this->_format_log(array($message), array($message_number)) . "\r\n</pre>\r\n";
                    flush();
                    ob_flush();
                    break;
                // basically the same thing as self::LOG_REALTIME with the caveat that self::LOG_REALTIME_FILE
                // needs to be defined and that the resultant log file will be capped out at self::LOG_MAX_SIZE.
                // the earliest part of the log file is denoted by the first <<< START >>> and is not going to necessarily
                // at the beginning of the file
                case self::LOG_REALTIME_FILE:
                    if (!isset($this->realtime_log_file)) {
                        // PHP doesn't seem to like using constants in fopen()
                        $filename = self::LOG_REALTIME_FILE;
                        $fp = fopen($filename, 'w');
                        $this->realtime_log_file = $fp;
                    }
                    if (!is_resource($this->realtime_log_file)) {
                        break;
                    }
                    $entry = $this->_format_log(array($message), array($message_number));
                    if ($this->realtime_log_wrap) {
                        $temp = "<<< START >>>\r\n";
                        $entry.= $temp;
                        fseek($this->realtime_log_file, ftell($this->realtime_log_file) - strlen($temp));
                    }
                    $this->realtime_log_size+= strlen($entry);
                    if ($this->realtime_log_size > self::LOG_MAX_SIZE) {
                        fseek($this->realtime_log_file, 0);
                        $this->realtime_log_size = strlen($entry);
                        $this->realtime_log_wrap = true;
                    }
                    fputs($this->realtime_log_file, $entry);
            }
    }

    /**
     * Sends channel data
     *
     * Spans multiple SSH_MSG_CHANNEL_DATAs if appropriate
     *
     * @param Integer $client_channel
     * @param String $data
     * @return Boolean
     * @access private
     */
    function _send_channel_packet($client_channel, $data)
    {
        while (strlen($data) > $this->packet_size_client_to_server[$client_channel]) {
            // resize the window, if appropriate
            $this->window_size_client_to_server[$client_channel]-= $this->packet_size_client_to_server[$client_channel];
            if ($this->window_size_client_to_server[$client_channel] < 0) {
                $packet = pack('CNN', self::MSG_CHANNEL_WINDOW_ADJUST, $this->server_channels[$client_channel], $this->window_size);
                if (!$this->_send_binary_packet($packet)) {
                    return false;
                }
                $this->window_size_client_to_server[$client_channel]+= $this->window_size;
            }

            $packet = pack('CN2a*',
                self::MSG_CHANNEL_DATA,
                $this->server_channels[$client_channel],
                $this->packet_size_client_to_server[$client_channel],
                $this->_string_shift($data, $this->packet_size_client_to_server[$client_channel])
            );

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }
        }

        // resize the window, if appropriate
        $this->window_size_client_to_server[$client_channel]-= strlen($data);
        if ($this->window_size_client_to_server[$client_channel] < 0) {
            $packet = pack('CNN', self::MSG_CHANNEL_WINDOW_ADJUST, $this->server_channels[$client_channel], $this->window_size);
            if (!$this->_send_binary_packet($packet)) {
                return false;
            }
            $this->window_size_client_to_server[$client_channel]+= $this->window_size;
        }

        return $this->_send_binary_packet(pack('CN2a*',
            self::MSG_CHANNEL_DATA,
            $this->server_channels[$client_channel],
            strlen($data),
            $data));
    }

    /**
     * Closes and flushes a channel
     *
     * Net_SSH2 doesn't properly close most channels.  For exec() channels are normally closed by the server
     * and for SFTP channels are presumably closed when the client disconnects.  This functions is intended
     * for SCP more than anything.
     *
     * @param Integer $client_channel
     * @return Boolean
     * @access private
     */
    function _close_channel($client_channel)
    {
        // see http://tools.ietf.org/html/rfc4254#section-5.3

        $this->_send_binary_packet(pack('CN', self::MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));

        $this->_send_binary_packet(pack('CN', self::MSG_CHANNEL_CLOSE, $this->server_channels[$client_channel]));

        $this->channel_status[$client_channel] = self::MSG_CHANNEL_CLOSE;

        $this->curTimeout = 0;

        while (!is_bool($this->_get_channel_packet($client_channel)));

        if ($this->bitmap & self::MASK_SHELL) {
            $this->bitmap&= ~self::MASK_SHELL;
        }
    }

    /**
     * Disconnect
     *
     * @param Integer $reason
     * @return Boolean
     * @access private
     */
    function _disconnect($reason)
    {
        if ($this->bitmap) {
            $data = pack('CNNa*Na*', self::MSG_DISCONNECT, $reason, 0, '', 0, '');
            $this->_send_binary_packet($data);
            $this->bitmap = 0;
            fclose($this->fsock);
            return false;
        }
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param String $string
     * @param optional Integer $index
     * @return String
     * @access private
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    /**
     * Returns a log of the packets that have been sent and received.
     *
     * Returns a string if self::$logging == self::LOG_COMPLEX, an array if self::$logging == self::LOG_SIMPLE and false if !self::$logging
     *
     * @access public
     * @return String or Array
     */
    function getLog()
    {
        if (!self::$logging) {
            return false;
        }

        switch (self::$logging) {
            case self::LOG_SIMPLE:
                return $this->message_number_log;
                break;
            case self::LOG_COMPLEX:
                return $this->_format_log($this->message_log, $this->message_number_log);
                break;
            default:
                return false;
        }
    }

    /**
     * Formats a log for printing
     *
     * @param Array $message_log
     * @param Array $message_number_log
     * @access private
     * @return String
     */
    function _format_log($message_log, $message_number_log)
    {
        static $boundary = ':', $long_width = 65, $short_width = 16;

        $output = '';
        for ($i = 0; $i < count($message_log); $i++) {
            $output.= $message_number_log[$i] . "\r\n";
            $current_log = $message_log[$i];
            $j = 0;
            do {
                if (!empty($current_log)) {
                    $output.= str_pad(dechex($j), 7, '0', STR_PAD_LEFT) . '0  ';
                }
                $fragment = $this->_string_shift($current_log, $short_width);
                $hex = substr(
                           preg_replace(
                               '#(.)#es',
                               '"' . $boundary . '" . str_pad(dechex(ord(substr("\\1", -1))), 2, "0", STR_PAD_LEFT)',
                               $fragment),
                           strlen($boundary)
                       );
                // replace non ASCII printable characters with dots
                // http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters
                // also replace < with a . since < messes up the output on web browsers
                $raw = preg_replace('#[^\x20-\x7E]|<#', '.', $fragment);
                $output.= str_pad($hex, $long_width - $short_width, ' ') . $raw . "\r\n";
                $j++;
            } while (!empty($current_log));
            $output.= "\r\n";
        }

        return $output;
    }

    /**
     * Returns all errors
     *
     * @return String
     * @access public
     */
    function getErrors()
    {
        return $this->errors;
    }

    /**
     * Returns the last error
     *
     * @return String
     * @access public
     */
    function getLastError()
    {
        return $this->errors[count($this->errors) - 1];
    }

    /**
     * Return the server identification.
     *
     * @return String
     * @access public
     */
    function getServerIdentification()
    {
        return $this->server_identifier;
    }

    /**
     * Return a list of the key exchange algorithms the server supports.
     *
     * @return Array
     * @access public
     */
    function getKexAlgorithms()
    {
        return $this->kex_algorithms;
    }

    /**
     * Return a list of the host key (public key) algorithms the server supports.
     *
     * @return Array
     * @access public
     */
    function getServerHostKeyAlgorithms()
    {
        return $this->server_host_key_algorithms;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getEncryptionAlgorithmsClient2Server()
    {
        return $this->encryption_algorithms_client_to_server;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getEncryptionAlgorithmsServer2Client()
    {
        return $this->encryption_algorithms_server_to_client;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getMACAlgorithmsClient2Server()
    {
        return $this->mac_algorithms_client_to_server;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getMACAlgorithmsServer2Client()
    {
        return $this->mac_algorithms_server_to_client;
    }

    /**
     * Return a list of the compression algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getCompressionAlgorithmsClient2Server()
    {
        return $this->compression_algorithms_client_to_server;
    }

    /**
     * Return a list of the compression algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getCompressionAlgorithmsServer2Client()
    {
        return $this->compression_algorithms_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getLanguagesServer2Client()
    {
        return $this->languages_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getLanguagesClient2Server()
    {
        return $this->languages_client_to_server;
    }

    /**
     * Returns the server public host key.
     *
     * Caching this the first time you connect to a server and checking the result on subsequent connections
     * is recommended.  Returns false if the server signature is not signed correctly with the public host key.
     *
     * @return Mixed
     * @access public
     */
    function getServerPublicHostKey()
    {
        $signature = $this->signature;
        $server_public_host_key = $this->server_public_host_key;

        extract(unpack('Nlength', $this->_string_shift($server_public_host_key, 4)));
        $this->_string_shift($server_public_host_key, $length);

        if ($this->signature_validated) {
            return $this->bitmap ?
                $this->signature_format . ' ' . base64_encode($this->server_public_host_key) :
                false;
        }

        $this->signature_validated = true;

        switch ($this->signature_format) {
            case 'ssh-dss':
                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $p = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $q = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $g = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $y = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                /* The value for 'dss_signature_blob' is encoded as a string containing
                   r, followed by s (which are 160-bit integers, without lengths or
                   padding, unsigned, and in network byte order). */
                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                if ($temp['length'] != 40) {
                    $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
                    throw new \Exception('Invalid signature', E_USER_NOTICE);
                }

                $r = new Math_BigInteger($this->_string_shift($signature, 20), 256);
                $s = new Math_BigInteger($this->_string_shift($signature, 20), 256);

                if ($r->compare($q) >= 0 || $s->compare($q) >= 0) {
                    $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
                    throw new \Exception('Invalid signature', E_USER_NOTICE);
                }

                $w = $s->modInverse($q);

                $u1 = $w->multiply(new Math_BigInteger(sha1($this->exchange_hash), 16));
                list(, $u1) = $u1->divide($q);

                $u2 = $w->multiply($r);
                list(, $u2) = $u2->divide($q);

                $g = $g->modPow($u1, $p);
                $y = $y->modPow($u2, $p);

                $v = $g->multiply($y);
                list(, $v) = $v->divide($p);
                list(, $v) = $v->divide($q);

                if (!$v->equals($r)) {
                    $this->_disconnect(self::DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                    throw new \Exception('Bad server signature', E_USER_NOTICE);
                }

                break;
            case 'ssh-rsa':
                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $e = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $n = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);
                $nLength = $temp['length'];

                /*
                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                $signature = $this->_string_shift($signature, $temp['length']);

                $rsa = new Crypt_RSA();
                $rsa->setSignatureMode(Crypt_RSA::SIGNATURE_PKCS1);
                $rsa->loadKey(array('e' => $e, 'n' => $n), Crypt_RSA::PUBLIC_FORMAT_RAW);
                if (!$rsa->verify($this->exchange_hash, $signature)) {
                    throw new \Exception('Bad server signature', E_USER_NOTICE);
                    return $this->_disconnect(self::DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
                */

                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                $s = new Math_BigInteger($this->_string_shift($signature, $temp['length']), 256);

                // validate an RSA signature per "8.2 RSASSA-PKCS1-v1_5", "5.2.2 RSAVP1", and "9.1 EMSA-PSS" in the
                // following URL:
                // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf

                // also, see SSHRSA.c (rsa2_verifysig) in PuTTy's source.

                if ($s->compare(new Math_BigInteger()) < 0 || $s->compare($n->subtract(new Math_BigInteger(1))) > 0) {
                    $this->_disconnect(self::DISCONNECT_KEY_EXCHANGE_FAILED);
                    throw new \Exception('Invalid signature', E_USER_NOTICE);
                }

                $s = $s->modPow($e, $n);
                $s = $s->toBytes();

                $h = pack('N4H*', 0x00302130, 0x0906052B, 0x0E03021A, 0x05000414, sha1($this->exchange_hash));
                $h = chr(0x01) . str_repeat(chr(0xFF), $nLength - 3 - strlen($h)) . $h;

                if ($s != $h) {
                    $this->_disconnect(self::DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                    throw new \Exception('Bad server signature', E_USER_NOTICE);
                }
                break;
            default:
                $this->_disconnect(self::DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                throw new \Exception('Unsupported signature format', E_USER_NOTICE);
        }

        return $this->signature_format . ' ' . base64_encode($this->server_public_host_key);
    }
}
