<?php

class Crypt_RC4_RC4Test extends Crypt_RC4_TestCase
{
    public $string = "The derp fox herped the super-derpity derp. :D";    
    public $password = "supersecure";
    public $key = "thisisakey";

    public function testRC4(){
        $this->assertRecoverable($this->string, $this->key);
    }

    public function testRC4_PBKDF2(){
        $this->assertRecoverable($this->string, false, $this->password);
    }

}
