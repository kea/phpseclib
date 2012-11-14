<?php

class Crypt_AES_AESTest extends Crypt_AES_TestCase
{
    public $string = "The derp fox herped the super-derpity derp. :D";    
    public $password = "supersecure";

    public function testAES(){
        foreach($this->modes as $mode)
            foreach($this->keylens as $keylen)
                $this->assertRecoverable($this->string, $mode, $keylen);
    }

    public function testAESPBKDF2(){
        foreach($this->modes as $mode){
            echo "ran $mode\n";
            $this->assertRecoverable($this->string, $mode, false, "supersecure");
        }
    }

}
