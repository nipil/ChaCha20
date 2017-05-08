<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ChaCha20\ChaCha20Block;
use ChaCha20\ChaCha20Exception;

final class ChaCha20BlockTest extends TestCase
{

    public function providerAddCap() {
        return [
            "no-overflow" => [
                0x77777777,
                0x01234567,
                0x789abcde],
            "signed-overflow" => [
                0x77767777,
                0x11239567,
                ChaCha20Block::buildUint32(0x889a, 0x0cde)],
            "unsigned-overflow" => [
                ChaCha20Block::buildUint32(0x8666, 0x6666),
                ChaCha20Block::buildUint32(0x8111, 0x1111),
                ChaCha20Block::buildUint32(0x0777, 0x7777)],
        ];
    }

    /**
     * @dataProvider providerAddCap
     */
    public function testAddCap(int $a, int $b, int $expected)
    {
        $this->assertEquals($expected, ChaCha20Block::add_cap($a, $b));
    }

    public function testCap()
    {
        if (PHP_INT_SIZE === 4) {
            $this->assertTrue(TRUE);
        } else {
            $this->assertEquals(0xFFFFFFFF, ChaCha20Block::cap(0x7FFFFFFFFFFFFFFF));
        }
    }

    public function providerRotLeft()
    {
        return [

            // rfc7539 test vector 2.1
            [0x7998bfda, 7, ChaCha20Block::buildUint32(0xcc5f, 0xed3c)],

            // failed at first on 32bit because >> pulled sign bits
            [ChaCha20Block::buildUint32(0xa59f, 0X595f), 7, ChaCha20Block::buildUint32(0xcfac, 0xafd2)],

            /**
             * following the discovery of the above failed test, the below set has been generated
             * the following dataset has been generated using assembly ROL instruction, via the following C program :

                #include <stdlib.h>
                #include <stdio.h>

                void rotate(int32_t value, int8_t left) {
                   printf("[ChaCha20Block::buildUint32(0x%04x, 0x%04x), ", (value >> 16) & 0xFFFF, value & 0xFFFF);
                   printf("%d, ", left);
                   asm("roll %1,%0" : "+r" (value) : "c" (left));
                   printf("ChaCha20Block::buildUint32(0x%04x, 0x%04x)],\n", (value >> 16) & 0xFFFF, value & 0xFFFF);
                }

                int main(void) {
                   int i = 0, j = 0;
                   time_t t;
                   int32_t sign = 0x80000000;
                   // recognizable bit pattern
                   int32_t value = 0b01011011101111000001000010001001;
                   int8_t left;
                   for (left=0; left<32; left++) {
                      rotate(value, left);
                   }
                   value |= sign;
                   for (left=0; left<32; left++) {
                      rotate(value, left);
                   }
                }
             */

            // all rotations of a int32 with MSB unset (no sign-bit)
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 0, ChaCha20Block::buildUint32(0x5bbc, 0x1089)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 1, ChaCha20Block::buildUint32(0xb778, 0x2112)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 2, ChaCha20Block::buildUint32(0x6ef0, 0x4225)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 3, ChaCha20Block::buildUint32(0xdde0, 0x844a)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 4, ChaCha20Block::buildUint32(0xbbc1, 0x0895)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 5, ChaCha20Block::buildUint32(0x7782, 0x112b)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 6, ChaCha20Block::buildUint32(0xef04, 0x2256)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 7, ChaCha20Block::buildUint32(0xde08, 0x44ad)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 8, ChaCha20Block::buildUint32(0xbc10, 0x895b)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 9, ChaCha20Block::buildUint32(0x7821, 0x12b7)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 10, ChaCha20Block::buildUint32(0xf042, 0x256e)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 11, ChaCha20Block::buildUint32(0xe084, 0x4add)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 12, ChaCha20Block::buildUint32(0xc108, 0x95bb)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 13, ChaCha20Block::buildUint32(0x8211, 0x2b77)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 14, ChaCha20Block::buildUint32(0x0422, 0x56ef)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 15, ChaCha20Block::buildUint32(0x0844, 0xadde)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 16, ChaCha20Block::buildUint32(0x1089, 0x5bbc)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 17, ChaCha20Block::buildUint32(0x2112, 0xb778)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 18, ChaCha20Block::buildUint32(0x4225, 0x6ef0)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 19, ChaCha20Block::buildUint32(0x844a, 0xdde0)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 20, ChaCha20Block::buildUint32(0x0895, 0xbbc1)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 21, ChaCha20Block::buildUint32(0x112b, 0x7782)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 22, ChaCha20Block::buildUint32(0x2256, 0xef04)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 23, ChaCha20Block::buildUint32(0x44ad, 0xde08)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 24, ChaCha20Block::buildUint32(0x895b, 0xbc10)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 25, ChaCha20Block::buildUint32(0x12b7, 0x7821)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 26, ChaCha20Block::buildUint32(0x256e, 0xf042)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 27, ChaCha20Block::buildUint32(0x4add, 0xe084)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 28, ChaCha20Block::buildUint32(0x95bb, 0xc108)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 29, ChaCha20Block::buildUint32(0x2b77, 0x8211)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 30, ChaCha20Block::buildUint32(0x56ef, 0x0422)],
            [ChaCha20Block::buildUint32(0x5bbc, 0x1089), 31, ChaCha20Block::buildUint32(0xadde, 0x0844)],

            // all rotations of a int32 with MSB set (sign-bit present)
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 0, ChaCha20Block::buildUint32(0xdbbc, 0x1089)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 1, ChaCha20Block::buildUint32(0xb778, 0x2113)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 2, ChaCha20Block::buildUint32(0x6ef0, 0x4227)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 3, ChaCha20Block::buildUint32(0xdde0, 0x844e)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 4, ChaCha20Block::buildUint32(0xbbc1, 0x089d)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 5, ChaCha20Block::buildUint32(0x7782, 0x113b)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 6, ChaCha20Block::buildUint32(0xef04, 0x2276)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 7, ChaCha20Block::buildUint32(0xde08, 0x44ed)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 8, ChaCha20Block::buildUint32(0xbc10, 0x89db)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 9, ChaCha20Block::buildUint32(0x7821, 0x13b7)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 10, ChaCha20Block::buildUint32(0xf042, 0x276e)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 11, ChaCha20Block::buildUint32(0xe084, 0x4edd)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 12, ChaCha20Block::buildUint32(0xc108, 0x9dbb)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 13, ChaCha20Block::buildUint32(0x8211, 0x3b77)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 14, ChaCha20Block::buildUint32(0x0422, 0x76ef)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 15, ChaCha20Block::buildUint32(0x0844, 0xedde)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 16, ChaCha20Block::buildUint32(0x1089, 0xdbbc)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 17, ChaCha20Block::buildUint32(0x2113, 0xb778)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 18, ChaCha20Block::buildUint32(0x4227, 0x6ef0)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 19, ChaCha20Block::buildUint32(0x844e, 0xdde0)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 20, ChaCha20Block::buildUint32(0x089d, 0xbbc1)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 21, ChaCha20Block::buildUint32(0x113b, 0x7782)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 22, ChaCha20Block::buildUint32(0x2276, 0xef04)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 23, ChaCha20Block::buildUint32(0x44ed, 0xde08)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 24, ChaCha20Block::buildUint32(0x89db, 0xbc10)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 25, ChaCha20Block::buildUint32(0x13b7, 0x7821)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 26, ChaCha20Block::buildUint32(0x276e, 0xf042)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 27, ChaCha20Block::buildUint32(0x4edd, 0xe084)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 28, ChaCha20Block::buildUint32(0x9dbb, 0xc108)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 29, ChaCha20Block::buildUint32(0x3b77, 0x8211)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 30, ChaCha20Block::buildUint32(0x76ef, 0x0422)],
            [ChaCha20Block::buildUint32(0xdbbc, 0x1089), 31, ChaCha20Block::buildUint32(0xedde, 0x0844)],
        ];
    }

    /**
     * @dataProvider providerRotLeft
     */
    public function testRotLeft($value, $left, $expected)
    {
        $this->assertEquals($expected, ChaCha20Block::rot_left($value, $left));
    }

    public function testXor()
    {
        // rfc7539 test vector 2.1
        $this->assertEquals(0x7998bfda, ChaCha20Block::xor(0x01020304, 0x789abcde));
    }

    public function testSetConstIndexValue()
    {
        $this->assertTrue(TRUE);
    }

    public function testSetKeyIndexValue()
    {
        $this->assertTrue(TRUE);
    }

    public function testSetNonceIndexValue()
    {
        $this->assertTrue(TRUE);
    }

    public function testSetCounter()
    {
        $this->assertTrue(TRUE);
    }

    public function testIncCounterNoOverflow()
    {
        $c = new ChaCha20Block();
        $c->set_counter(0x12345678);
        $c->inc_counter(0x12341111);
        $this->assertEquals(0x24686789, $c->get_counter());
    }

    public function testIncCounterSignedOverflow()
    {
        $c = new ChaCha20Block();
        $c->set_counter(0x72345678);
        $c->inc_counter(0x12341111);
        $this->assertEquals(
            ChaCha20Block::buildUint32(0x8468, 0x6789),
            $c->get_counter());
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testIncCounterUnsignedOverflow()
    {
        $c = new ChaCha20Block();
        $c->set_counter(ChaCha20Block::buildUint32(0x8001, 0x8001));
        $c->inc_counter(ChaCha20Block::buildUint32(0x8002, 0x8002));
        printf("0x%08x\n", $c->get_counter());
    }

    public function testBinToInternal()
    {
        $this->assertTrue(TRUE);
    }

    public function testSetKey()
    {
        $this->assertTrue(TRUE);
    }

    public function testSetNonce()
    {
        $this->assertTrue(TRUE);
    }

    public function testQuarterRound()
    {
        // rfc7539 test vector 2.2.1

        $vector = [
            ChaCha20Block::buildUint32(0x8795, 0x31e0),
            ChaCha20Block::buildUint32(0xc5ec, 0xf37d),
            0x516461b1, // 2
            ChaCha20Block::buildUint32(0xc9a6, 0x2f8a),
            0x44c20ef3,
            0x3390af7f,
            ChaCha20Block::buildUint32(0xd9fc, 0x690b),
            0x2a5f714c, // 7
            0x53372767, // 8
            ChaCha20Block::buildUint32(0xb00a, 0x5631),
            ChaCha20Block::buildUint32(0x974c, 0x541a),
            0x359e9963,
            0x5c971061,
            0x3d631689, // 13
            0x2098d9d6,
            ChaCha20Block::buildUint32(0x91db, 0xd320)
        ];

        ChaCha20Block::do_quarter_round(2, 7, 8, 13, $vector);

        $this->assertEquals([
                ChaCha20Block::buildUint32(0x8795, 0x31e0),
                ChaCha20Block::buildUint32(0xc5ec, 0xf37d),
                ChaCha20Block::buildUint32(0xbdb8, 0x86dc), // 2
                ChaCha20Block::buildUint32(0xc9a6, 0x2f8a),
                0x44c20ef3,
                0x3390af7f,
                ChaCha20Block::buildUint32(0xd9fc, 0x690b),
                ChaCha20Block::buildUint32(0xcfac, 0xafd2), // 7
                ChaCha20Block::buildUint32(0xe46b, 0xea80), // 8
                ChaCha20Block::buildUint32(0xb00a, 0x5631),
                ChaCha20Block::buildUint32(0x974c, 0x541a),
                0x359e9963,
                0x5c971061,
                ChaCha20Block::buildUint32(0xccc0, 0x7c79), // 13
                0x2098d9d6,
                ChaCha20Block::buildUint32(0x91db, 0xd320)
            ],
            $vector);
    }

    public function testConstructorEmpty()
    {
        // rfc7539 test vector 2.3.2
        $c = new ChaCha20Block();

        // initial
        $this->assertEquals([
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000
            ],
            $c->get_state(ChaCha20Block::STATE_INITIAL),
            "clear state failed");

        // check counter
        $this->assertEquals(0, $c->get_counter());
    }

    public function testConstructorValued()
    {
        // rfc7539 test vector 2.3.2
        $key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        $nonce = "000000090000004a00000000";
        $ctr = 1;

        // valued constructor
        $c = new ChaCha20Block(hex2bin($key), hex2bin($nonce), $ctr);

        // initial
        $this->assertEquals([
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x00000001, 0x09000000, 0x4a000000, 0x00000000
            ],
            $c->get_state(ChaCha20Block::STATE_INITIAL),
            "initial state failed");

        // check counter
        $this->assertEquals(1, $c->get_counter());

        // provides
        return $c;
    }

    /**
     * @depends testConstructorValued
     */
    public function testComputeBlock($c)
    {
        // compute
        $c->compute_block();

        // intermediate
        $this->assertEquals([
                ChaCha20Block::buildUint32(0x8377, 0x78ab),
                ChaCha20Block::buildUint32(0xe238, 0xd763),
                ChaCha20Block::buildUint32(0xa67a, 0xe21e),
                0x5950bb2f,
                ChaCha20Block::buildUint32(0xc4f2, 0xd0c7),
                ChaCha20Block::buildUint32(0xfc62, 0xbb2f),
                ChaCha20Block::buildUint32(0x8fa0, 0x18fc),
                0x3f5ec7b7,
                0x335271c2,
                ChaCha20Block::buildUint32(0xf294, 0x89f3),
                ChaCha20Block::buildUint32(0xeabd, 0xa8fc),
                ChaCha20Block::buildUint32(0x82e4, 0x6ebd),
                ChaCha20Block::buildUint32(0xd19c, 0x12b4),
                ChaCha20Block::buildUint32(0xb04e, 0x16de),
                ChaCha20Block::buildUint32(0x9e83, 0xd0cb),
                0x4e3c50a2
            ],
            $c->get_state(ChaCha20Block::STATE_INTERMEDIATE),
            "intermediate state failed");

        // final
        $this->assertEquals([
                ChaCha20Block::buildUint32(0xe4e7, 0xf110),
                0x15593bd1,
                0x1fdd0f50,
                ChaCha20Block::buildUint32(0xc471, 0x20a3),
                ChaCha20Block::buildUint32(0xc7f4, 0xd1c7),
                0x0368c033,
                ChaCha20Block::buildUint32(0x9aaa, 0x2204),
                0x4e6cd4c3,
                0x466482d2,
                0x09aa9f07,
                0x05d7c214,
                ChaCha20Block::buildUint32(0xa202, 0x8bd9),
                ChaCha20Block::buildUint32(0xd19c, 0x12b5),
                ChaCha20Block::buildUint32(0xb94e, 0x16de),
                ChaCha20Block::buildUint32(0xe883, 0xd0cb),
                0x4e3c50a2
            ],
            $c->get_state(ChaCha20Block::STATE_FINAL),
            "final state failed");

        // serialize
        $this->assertEquals(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            bin2hex($c->serialize_state(ChaCha20Block::STATE_FINAL)),
            "serialize failed");
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionRotate()
    {
        ChaCha20Block::rot_left(0, -1);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionSetConstIndexValue()
    {
        $c = new ChaCha20Block();
        $c->set_const_index_value(-1, 0);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionSetKeyIndexValue()
    {
        $c = new ChaCha20Block();
        $c->set_key_index_value(-1, 0);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionSetNonceIndexValue()
    {
        $c = new ChaCha20Block();
        $c->set_nonce_index_value(-1, 0);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionBinToInternalTooLong()
    {
        $c = new ChaCha20Block();
        $c->bin_to_initial("toolong", "test", 0, 0);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionBinToInternalInvalidIndex()
    {
        $c = new ChaCha20Block();
        $c->bin_to_initial("", "test", -1, 0);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionBinToInternalInvalidLength()
    {
        $c = new ChaCha20Block();
        $c->bin_to_initial("", "test", 0, -1);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionBinToInternalTotalTooLong()
    {
        $c = new ChaCha20Block();
        $c->bin_to_initial(
            "12345678901234567890123456789012",
            "test",
            0,
            ChaCha20Block::STATE_ARRAY_LENGTH + 1);
    }
}
