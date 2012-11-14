<?php
/**
 * @author     Katelyn Schiesser <katelyn.schiesser@gmail.com>
 */
use phpseclib\Crypt_TripleDES;
use phpseclib\Crypt_DES;
use phpseclib\Crypt_Hash;

abstract class Crypt_TripleDES_TestCase extends PHPUnit_Framework_TestCase
{
    public $modes = array(
        Crypt_DES::MODE_ECB,
        Crypt_DES::MODE_CBC,
        Crypt_DES::MODE_CTR,
        Crypt_DES::MODE_OFB,
        Crypt_DES::MODE_CFB,
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

	protected function assertRecoverable($string, $mode, $key, $password=false)
	{
        $cipher = new Crypt_TripleDES($mode);
        if($password)
            $cipher->setPassword($password);
        else
            $cipher->setKey($key);
        $encrypted = $cipher->encrypt($string);
        $decrypted = $cipher->decrypt($encrypted);
		$this->assertEquals(
			$string,
			$decrypted,
			sprintf("Failed recovery with mode %s, key '%s', password '%s'. Asserting that '%s' equals to '%s'.", $mode, $key, $password, $string, $decrypted)
		);
	}

}
