<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ChaCha20\ChaCha20Exception;
use ChaCha20\ChaCha20Block;
use ChaCha20\ChaCha20Random;
use ChaCha20\ChaCha20Cipher;

/**
 * @covers ChaCha20Cipher
 */
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

        // initial
        $this->assertEquals([
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x00000001, 0x00000000, 0x4a000000, 0x00000000
            ],
            $c->get_state(ChaCha20Block::STATE_INITIAL),
            "1st initial state failed");

        // check counter
        $this->assertEquals(1, $c->get_counter());

        // check counter
        $this->assertEquals(0, $c->get_sub_counter());

        // 1st block final
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
    }

    /**
     * @depends testConstructorValued
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionSubCounter($c)
    {
        $c->set_sub_counter(64);
    }
}
