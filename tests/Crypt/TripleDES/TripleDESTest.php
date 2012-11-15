<?php

class Crypt_TripleDES_TripleDESTest extends Crypt_TripleDES_TestCase
{
    public $string = "The derp fox herped the super-derpity derp. :D!!";    
    public $password = "supersecure";
    public $key = "thisisakey";

    public function testTripleDES(){
        foreach($this->modes as $mode)
            $this->assertRecoverable($this->string, $mode, $this->key);
    }

    public function testTripleDES_PBKDF2(){
        foreach($this->modes as $mode)
            $this->assertRecoverable($this->string, $mode, false, $this->password);
    }

}
