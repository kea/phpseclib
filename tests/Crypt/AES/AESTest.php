<?php

class Crypt_AES_AESTest extends Crypt_AES_TestCase
{
    
    public function testAES(){
        $string = "The derp fox herped the super-derpity derp. :D";
        foreach($this->modes as $mode)
            foreach($this->keylens as $keylen)
                $this->assertRecoverable($string, $mode, $keylen);
    }

}
