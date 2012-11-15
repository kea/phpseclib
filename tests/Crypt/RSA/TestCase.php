<?php
/**
 * @author     Katelyn Schiesser <katelyn.schiesser@gmail.com>
 */
use phpseclib\Crypt_RSA;
use phpseclib\Crypt_Hash;

abstract class Crypt_RSA_TestCase extends PHPUnit_Framework_TestCase
{

    public $privateModes = array(
        Crypt_RSA::PUBLIC_FORMAT_PKCS1,
        Crypt_RSA::PRIVATE_FORMAT_PUTTY,
        Crypt_RSA::PRIVATE_FORMAT_XML,
    );

    public $publicModes = array(
        Crypt_RSA::PUBLIC_FORMAT_PKCS1,
        Crypt_RSA::PUBLIC_FORMAT_OPENSSH,
        Crypt_RSA::PUBLIC_FORMAT_XML
    );

    public $signatureModes = array(
        Crypt_RSA::SIGNATURE_PSS,
        Crypt_RSA::SIGNATURE_PKCS1,
    );

    public $encryptionModes = array(
        Crypt_RSA::ENCRYPTION_OAEP,
        Crypt_RSA::ENCRYPTION_PKCS1,
    );

    public $keylens = array(
        1024,
        2048,
        4096,
    );


    static public function setUpBeforeClass()
    {
        if (!defined('CRYPT_HASH_MODE'))
        {
            define('CRYPT_HASH_MODE', Crypt_Hash::MODE_INTERNAL);
        }
    }

    public function setUp()
    {
        if (defined('CRYPT_HASH_MODE') && CRYPT_HASH_MODE !== Crypt_Hash::MODE_INTERNAL)
        {
            $this->markTestSkipped('Skipping test because CRYPT_HASH_MODE is not defined as Crypt_Hash::MODE_INTERNAL.');
        }
    }

    public function generateRsaKeypair(){
        $rsa = new Crypt_RSA;
        return $rsa->createKey();
    }

    protected function assertCreateKeypair($keylen, $privMode, $pubMode, $password=false, $timeout=false){
        echo "assertCreateKeypair($keylen, $privMode, $pubMode, '$password', '$timeout')\n";
        $rsa = new Crypt_RSA;
        $rsa->setPrivateKeyFormat($privMode);
        $rsa->setPublicKeyFormat($pubMode);
        if($password && $privMode != Crypt_RSA::PRIVATE_FORMAT_XML)
            $rsa->setPassword($password);
        elseif($password)
            return false;
        extract($rsa->createKey($keylen, $timeout));
        $this->assertThat(false, $this->logicalNot($this->equalTo($privatekey)),
            sprintf("Assertion that privatekey != false failed for keylen %s, privMode %s, pubMode %s, timeout %s", $keylen, $privMode, $pubMode, $timeout));
        $this->assertThat(false, $this->logicalNot($this->equalTo($publickey)),
            sprintf("Assertion that publickey != false failed for keylen %s, privMode %s, pubMode %s, timeout %s", $keylen, $privMode, $pubMode, $timeout));
    }

	protected function assertRecoverable($string, $mode)
	{
        $keypair = $this->generateRsaKeypair();
        $rsa = new Crypt_RSA;
        $rsa->setEncryptionMode($mode);
        $rsa->loadKey($keypair['publickey']);
        $encrypted = $rsa->encrypt($string);
        $rsa->loadKey($keypair['privatekey']);
        $decrypted = $rsa->decrypt($encrypted);
		$this->assertEquals(
			$string,
			$decrypted,
			sprintf("Failed recovery with mode %s. Asserting that '%s' equals to '%s'.", $mode, $string, $decrypted)
		);
	}

    protected function assertSignatureVerifiable($string, $mode, $password=false){
        $keypair = $this->generateRsaKeypair();
        $rsa = new Crypt_RSA;
        if($password)
            $rsa->setPassword($password);
        $rsa->loadKey($keypair['privatekey']);
        $sig = $rsa->sign($string);
        $this->assertThat($sig, $this->logicalNot($this->equalTo(false)),
            sprintf("Failed to sign string '%s' with mode %s, password '%s'", $string, $mode, $password));
        $rsa->loadKey($keypair['publickey']);
        $ver = $rsa->verify($string, $sig);
        $this->assertTrue($ver, sprintf('Key verification failed for mode %s, password \'%s\', string \'%s\'', $mode, $password, $string));
    }

}
