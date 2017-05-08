<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ChaCha20\ChaCha20Exception;
use ChaCha20\ChaCha20Block;
use ChaCha20\ChaCha20Random;

/**
 * @covers ChaCha20\ChaCha20Random
 */
final class ChaCha20RandomTest extends TestCase
{
    public function testConstructorEmpty()
    {
        $r = new ChaCha20Random();
        $s = $r->get_state(ChaCha20Random::STATE_INITIAL);

        // verify constants
        $c = array_slice($s,
            ChaCha20Random::STATE_CONST_BASEINDEX,
            ChaCha20Random::STATE_CONST_LENGTH);
        $this->assertEquals([
                ChaCha20Random::CONSTANT_VALUE_0,
                ChaCha20Random::CONSTANT_VALUE_1,
                ChaCha20Random::CONSTANT_VALUE_2,
                ChaCha20Random::CONSTANT_VALUE_3
            ], $c);

        // verify key (not all zero)
        $k = array_slice($s,
            ChaCha20Random::STATE_KEY_BASEINDEX,
            ChaCha20Random::STATE_KEY_LENGTH);
        $this->assertNotEquals(
            array_fill(0, ChaCha20Random::STATE_KEY_LENGTH, 0),
            $k);

        // verify nonce (not all zero)
        $n = array_slice($s,
            ChaCha20Random::STATE_NONCE_BASEINDEX,
            ChaCha20Random::STATE_NONCE_LENGTH);
        $this->assertNotEquals(
            array_fill(0, ChaCha20Random::STATE_NONCE_LENGTH, 0),
            $n);
    }

    /**
     * @expectedException ChaCha20\ChaCha20Exception
     */
    public function testExceptionSubCounter()
    {
        $r = new ChaCha20Random();
        $r->set_sub_counter(-1);
    }

    public function testMultipleRand()
    {
        $r = new ChaCha20Random(NULL, NULL, 123456789, 12);
        $this->assertEquals(123456789, $r->get_counter());
        $this->assertEquals(12, $r->get_sub_counter());
        for ($i = 0; $i < 20; $i++) {
            $v = $r->rand();
        }
        $this->assertEquals(123456791, $r->get_counter());
        $this->assertEquals(0, $r->get_sub_counter());
    }
}
