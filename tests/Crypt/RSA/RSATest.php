<?php

class Crypt_RSA_RSATest extends Crypt_RSA_TestCase
{
    public $string = "The derp fox herped the super-derpity derp. :D";    
    public $password = "supersecure";

    public function testCreateKey(){
        foreach(array(false, $this->password))
            foreach($this->keylens as $keylen)
                foreach($this->privateModes as $privMode)
                    foreach($this->publicModes as $pubMode)
                        $this->assertCreateKeypair($keylen, $privMode, $pubMode);
    }

    public function testCreateVerifySignature(){
        $passArray = array(false, $this->password);
        foreach($passArray as $password)
            foreach($this->signatureModes as $sigMode)
                $this->assertSignatureVerifiable($this->string, $sigMode, $password);
    }

    public function testEncryptDecryptMessage(){
        foreach($this->encryptionModes as $mode)
            $this->assertRecoverable($this->string, $mode);
    }

}
