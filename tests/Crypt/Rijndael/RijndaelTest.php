<?php

class Crypt_Rijndael_RijndaelTest extends Crypt_Rijndael_TestCase
{
    public $string = "The derp fox herped the super-derpity derp. :D";    
    public $password = "supersecure";

    public function testRijndael(){
        foreach($this->modes as $mode)
            foreach($this->keylens as $keylen)
                foreach($this->blocklens as $blocklen)
                    $this->assertRecoverable($this->string, $mode, $keylen, $blocklen);
    }

    public function testRijndael_PBKDF2(){
        foreach($this->modes as $mode)
            foreach($this->blocklens as $blocklen)
                $this->assertRecoverable($this->string, $mode, false, $blocklen, $this->password);
    }

}
