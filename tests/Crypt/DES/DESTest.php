<?php

class Crypt_DES_DESTest extends Crypt_DES_TestCase
{
    public $string = "The derp fox herped the super-derpity derp. :D";    
    public $password = "supersecure";
    public $key = "thisisakey";

    public function testDES(){
        foreach($this->modes as $mode)
            $this->assertRecoverable($this->string, $mode, $this->key);
    }

    public function testDES_PBKDF2(){
        foreach($this->modes as $mode)
            $this->assertRecoverable($this->string, $mode, false, $this->password);
    }

}
