<?php

declare(strict_types=1);

namespace ChaCha20;

/**
 * Does XOR encrypts/decrypt on input
 *
 * Uses random data from ChaCha20Block
 */
class ChaCha20Cipher extends ChaCha20Block {

    /**
     * cache block output
     */
    private $random_string;

    /**
     * block_sub_index is the integer index in the current block
     **/

    private $block_sub_index;

    public function set_sub_counter(int $index) {
        if ($index < 0 or $index >= ChaCha20Block::STATE_ARRAY_LENGTH * ChaCha20Block::INT_BIT_LENGTH >> 3) {
            throw new ChaCha20Exception(sprintf("Sub-counter index %d is outstide range [0..%d[", $index, ChaCha20Block::STATE_KEY_LENGTH.'['));
        }
        $this->block_sub_index = $index;
    }

    public function get_sub_counter() {
        return $this->block_sub_index;
    }

    /**
     * creates a cipher object
     */
    public function __construct(string $key, string $nonce, int $block_ctr, int $block_sub_ctr) {

        // initialize ChaCha20Block
        parent::__construct($key, $nonce, $block_ctr);

        // initialize state index
        $this->block_sub_index = $block_sub_ctr;

        // compute first block of data
        $this->compute_block();
        $this->random_string = $this->serialize_state(ChaCha20Random::STATE_FINAL);
    }

    /**
     * does encryption/recryption on the provided string
     */
    public function transform(string $input)
    {
        // build a copy of same length to work on
        $output = $input;

        // encrypt input, one byte at a time
        for ($i = 0; $i < strlen($input); $i++)
        {
            // if end of current block, generate a new one
            if ($this->block_sub_index == ChaCha20Block::STATE_ARRAY_LENGTH * ChaCha20Block::INT_BIT_LENGTH >> 3)
            {
                $this->block_sub_index = 0;
                $this->inc_counter();
                $this->compute_block();
                $this->random_string = $this->serialize_state(ChaCha20Random::STATE_FINAL);
            }

            // encrypt single byte
            $in_byte = $input[$i];
            $key_byte = $this->random_string[$this->block_sub_index];
            $out_byte_ord = ord($in_byte) ^ ord($key_byte);
            $output[$i] = chr($out_byte_ord);
            $this->block_sub_index++;
        }

        return $output;
    }
}
