<?php
/**
 * @author     Katelyn Schiesser <katelyn.schiesser@gmail.com>
 */
use phpseclib\Crypt_RC4;
use phpseclib\Crypt_Hash;

abstract class Crypt_RC4_TestCase extends PHPUnit_Framework_TestCase
{
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

	protected function assertRecoverable($string, $key, $password=false)
	{
        $cipher = new Crypt_RC4();
        if($password)
            $cipher->setPassword($password);
        else
            $cipher->setKey($key);
        $encrypted = $cipher->encrypt($string);
        $decrypted = $cipher->decrypt($encrypted);
		$this->assertEquals(
			$string,
			$decrypted,
			sprintf("Failed recovery with key '%s', password '%s' Asserting that '%s' equals to '%s'.",
                $key, $password, $string, $decrypted)
		);
	}

}
