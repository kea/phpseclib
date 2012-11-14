<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt_AES;

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


	public function setUp()
	{

	}

	protected function assertRecoverable($string, $mode, $keylen)
	{
        $cipher = new Crypt_AES($mode);
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
