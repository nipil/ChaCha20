<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ChaCha20\ChaCha20Exception;
use ChaCha20\ChaCha20Block;
use ChaCha20\ChaCha20Random;
use ChaCha20\ChaCha20Cipher;

final class ChaCha20CipherTest extends TestCase
{

    public function testConstructorValued()
    {
        // rfc7539 test vector 2.3.2
        $key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        $nonce = "000000000000004a00000000";
        $ctr = 1;

        // valued constructor
        $c = new ChaCha20Cipher(hex2bin($key), hex2bin($nonce), $ctr, 0);

        // first block setup
        $this->assertEquals([
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x00000001, 0x00000000, 0x4a000000, 0x00000000
            ],
            $c->get_state(ChaCha20Block::STATE_INITIAL),
            "1st initial state failed");

        // check counter before operation
        $this->assertEquals(1, $c->get_counter());

        // check counter before operation
        $this->assertEquals(0, $c->get_sub_counter());

        // first block after block operation
        $this->assertEquals([
                ChaCha20Block::buildUint32(0xf351, 0x4f22),
                ChaCha20Block::buildUint32(0xe1d9, 0x1b40),
                0x6f27de2f,
                ChaCha20Block::buildUint32(0xed1d, 0x63b8),
                ChaCha20Block::buildUint32(0x821f, 0x138c),
                ChaCha20Block::buildUint32(0xe206, 0x2c3d),
                ChaCha20Block::buildUint32(0xecca, 0x4f7e),
                0x78cff39e,
                ChaCha20Block::buildUint32(0xa30a, 0x3b8a),
                ChaCha20Block::buildUint32(0x920a, 0x6072),
                ChaCha20Block::buildUint32(0xcd74, 0x79b5),
                0x34932bed,
                0x40ba4c79,
                ChaCha20Block::buildUint32(0xcd34, 0x3ec6),
                0x4c2c21ea,
                ChaCha20Block::buildUint32(0xb741, 0x7df0),
            ],
            $c->get_state(ChaCha20Block::STATE_FINAL),
            "1st final state failed");

        // provides
        return $c;
    }

    /**
     * @depends testConstructorValued
     */

    public function testCipher($c)
    {
        // rfc7539 test vector 2.4.2

        $key_stream_1st_block = $c->serialize_state(ChaCha20Block::STATE_FINAL);

        $input = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        $this->assertEquals(114, strlen($input), "invalid input length");

        $this->assertEquals(
            "4c616469657320616e642047656e746c"
            . "656d656e206f662074686520636c6173"
            . "73206f66202739393a20496620492063"
            . "6f756c64206f6666657220796f75206f"
            . "6e6c79206f6e652074697020666f7220"
            . "746865206675747572652c2073756e73"
            . "637265656e20776f756c642062652069"
            . "742e",
            bin2hex($input),
            "invalid input content");

        $output = $c->transform($input);

        $this->assertEquals(114, strlen($output), "invalid input length");

        // second block setup
        $this->assertEquals([
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x00000002, 0x00000000, 0x4a000000, 0x00000000
            ],
            $c->get_state(ChaCha20Block::STATE_INITIAL),
            "2nd initial state failed");

        // check counter after operation
        $this->assertEquals(2, $c->get_counter());

        // check counter after operation
        $this->assertEquals(50, $c->get_sub_counter());

        // second block after block operation
        $this->assertEquals([
                ChaCha20Block::buildUint32(0x9f74, 0xa669),
                0x410f633f,
                0x28feca22,
                0x7ec44dec,
                0x6d34d426,
                0x738cb970,
                0x3ac5e9f3,
                0x45590cc4,
                ChaCha20Block::buildUint32(0xda6e, 0x8b39),
                ChaCha20Block::buildUint32(0x892c, 0x831a),
                ChaCha20Block::buildUint32(0xcdea, 0x67c1),
                0x2b7e1d90,
                0x037463f3,
                ChaCha20Block::buildUint32(0xa11a, 0x2073),
                ChaCha20Block::buildUint32(0xe8bc, 0xfb88),
                ChaCha20Block::buildUint32(0xedc4, 0x9139)
            ],
            $c->get_state(ChaCha20Block::STATE_FINAL),
            "2nd final state failed");

        $key_stream_2nd_block = $c->serialize_state(ChaCha20Block::STATE_FINAL);

        $key_steam = substr($key_stream_1st_block . $key_stream_2nd_block, 0, 114);

        $this->assertEquals(
            "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06"
            . "e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b"
            . "9334794cba40c63e34cdea212c4cf07d41b769a6749f3f"
            . "630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a"
            . "c40c5945398b6eda1a832c89c167eacd901d7e2bf363",
            bin2hex($key_steam), "invalid key_stream");

        $this->assertEquals(
            "6e2e359a2568f98041ba0728dd0d6981"
            ."e97e7aec1d4360c20a27afccfd9fae0b"
            ."f91b65c5524733ab8f593dabcd62b357"
            ."1639d624e65152ab8f530c359f0861d8"
            ."07ca0dbf500d6a6156a38e088a22b65e"
            ."52bc514d16ccf806818ce91ab7793736"
            ."5af90bbf74a35be6b40b8eedf2785e42"
            ."874d",
            bin2hex($output),
            "invalid cipher_text");
    }

    /**
     * @depends testConstructorValued
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionSubCounterOverload($c)
    {
        $c->set_sub_counter(64);
    }

    /**
     * @depends testConstructorValued
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionSubCounterNegative($c)
    {
        $c->set_sub_counter(-1);
    }

    /**
     * @depends testConstructorValued
     */
    public function testSubCounter($c)
    {
        $n = ChaCha20Block::STATE_ARRAY_LENGTH * ChaCha20Block::INT_BIT_LENGTH >> 3;
        for ($i=0; $i<$n; $i++) {
            $c->set_sub_counter($i);
            $this->assertEquals(
                $i,
                $c->get_sub_counter(),
                sprintf("sub counter test %d", $i));
        }
    }
}
