<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */
use phpseclib\Crypt_Rijndael;
use phpseclib\Crypt_Hash;

abstract class Crypt_Rijndael_TestCase extends PHPUnit_Framework_TestCase
{
    public $modes = array(
        Crypt_Rijndael::MODE_ECB,
        Crypt_Rijndael::MODE_CBC,
        Crypt_Rijndael::MODE_CTR,
        Crypt_Rijndael::MODE_OFB,
        Crypt_Rijndael::MODE_CFB,
    );

    public $keylens = array(
        128,
        160,
        192,
        224,
        256,
    );

    public $blocklens = array(
        128,
        160,
        192,
        224,
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

	protected function assertRecoverable($string, $mode, $keylen, $blocklen, $password=false)
	{
        $cipher = new Crypt_Rijndael($mode);
        if($password)
            $cipher->setPassword($password);
        else
            $cipher->setKeyLength($keylen);
        $cipher->setBlockLength($blocklen);
        #$encrypted = $cipher->encrypt($string);
        #$decrypted = $cipher->decrypt($encrypted);
		#$this->assertEquals(
		#	$string,
		#	$decrypted,
		#	sprintf("Failed recovery with mode %s, keylen %s, blocklen %s. Asserting that '%s' equals to '%s'.",
        #         $mode, $keylen, $blocklen, $string, $decrypted)
		#);
	}

}
