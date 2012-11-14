<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */
use phpseclib\Crypt_AES;
use phpseclib\Crypt_Hash;

abstract class Crypt_AES_TestCase extends PHPUnit_Framework_TestCase
{
    public $modes = array(
        Crypt_AES::MODE_ECB,
        Crypt_AES::MODE_CBC,
        Crypt_AES::MODE_CTR,
        Crypt_AES::MODE_OFB,
        Crypt_AES::MODE_CFB,
    );

    public $keylens = array(
        128,
        192,
        256,
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

	protected function assertRecoverable($string, $mode, $keylen, $password=false)
	{
        $cipher = new Crypt_AES($mode);
        if($password)
            $cipher->setPassword($password);
        else
            $cipher->setKeyLength($keylen);
        $encrypted = $cipher->encrypt($string);
        $decrypted = $cipher->decrypt($encrypted);
		$this->assertEquals(
			$string,
			$decrypted,
			sprintf("Failed recovery with mode %s, keylen %s. Asserting that '%s' equals to '%s'.", $mode, $keylen, $string, $decrypted)
		);
	}

}
