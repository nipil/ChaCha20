<?php

declare(strict_types=1);

namespace ChaCha20;

/**
 * Generates PRNG, providing uint32 by using a ChaCha20 blocks
 */
class ChaCha20Random extends ChaCha20Block {

    /**
     * cache block output
     */
    private $random_data;

    /**
     * block_sub_index is the integer index in the current block
     **/

    private $block_sub_index;

    public function set_sub_counter(int $index) {
        if ($index < 0 or $index >= ChaCha20Block::STATE_ARRAY_LENGTH) {
            throw new ChaCha20Exception(sprintf(
                "Sub-counter index %d is outstide range [0..%d[",
                $index,
                ChaCha20Block::STATE_ARRAY_LENGTH));
        }
        $this->block_sub_index = $index;
    }

    public function get_sub_counter() {
        return $this->block_sub_index;
    }

    /**
     * generates a key from /dev/urandom
     */
    public static function weak_random_key() {
        return $str = random_bytes(
            ChaCha20Block::STATE_KEY_LENGTH
            * ChaCha20Block::INT_BIT_LENGTH
            >> 3);
    }

    /**
     * generates a nonce from /dev/urandom
     */
    public static function weak_random_nonce() {
        return random_bytes(
            ChaCha20Block::STATE_NONCE_LENGTH
            * ChaCha20Block::INT_BIT_LENGTH
            >> 3);
    }

    /**
     * generates a counter from /dev/urandom
     */
    public static function weak_random_counter() {
        $str = random_bytes(
            ChaCha20Block::INT_BIT_LENGTH
            >> 3);
        return unpack("V1", $str)[1];
    }

    /**
     * generates a sub-counter from /dev/urandom
     */
    public static function weak_random_sub_counter() {
        $str = random_bytes(1);
        $value = ord($str[0]) % ChaCha20Block::STATE_ARRAY_LENGTH;
        return $value;
    }

    /**
     * generates an PRNG object (possibly randomized)
     */
    public function __construct(string $key=NULL, string $nonce=NULL, int $block_ctr=NULL, int $block_sub_ctr = NULL) {

        // provide random if necessary
        if ($key === NULL) {
            $key = self::weak_random_key();
        }
        if ($nonce === NULL) {
            $nonce = self::weak_random_nonce();
        }
        if ($block_ctr === NULL) {
            $block_ctr = self::weak_random_counter();
        }
        if ($block_sub_ctr === NULL) {
            $block_sub_ctr = self::weak_random_sub_counter();
        }

        // initialize ChaCha20Block
        parent::__construct($key, $nonce, $block_ctr);

        // initialize state index
        $this->set_sub_counter($block_sub_ctr);

        // compute first block of data
        $this->compute_block();
        $this->random_data = $this->get_state(ChaCha20Random::STATE_FINAL);
    }

    /**
     * provide a random integer (int32) for each call
     */
    public function rand()
    {
        // get
        $value = $this->random_data[$this->block_sub_index];
        $this->block_sub_index++;

        // end of block, calculate another
        if ($this->block_sub_index == ChaCha20Block::STATE_ARRAY_LENGTH)
        {
            $this->block_sub_index = 0;
            $this->inc_counter();
            $this->compute_block();
            $this->random_data = $this->get_state(ChaCha20Random::STATE_FINAL);
        }

        return $value;
    }
}
