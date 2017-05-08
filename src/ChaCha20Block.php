<?php

declare(strict_types=1);

namespace ChaCha20;

/**
 * Calculates ChaCha20 blocks based on a given (key, nonce, ctr) set
 */
class ChaCha20Block {

    /**
     * ChaCha20 works on 32-bit integers
     */
    const INT_BIT_LENGTH = 32;
    const INT_BIT_HALF_LENGTH = ChaCha20Block::INT_BIT_LENGTH >> 1;
    const INT_BIT_HALFMASK = 0xFFFF;

    // make sure it's an integer on 32-bits platforms
    const INT_BIT_MASK =
        ChaCha20Block::INT_BIT_HALFMASK
        << ChaCha20Block::INT_BIT_HALF_LENGTH
        | ChaCha20Block::INT_BIT_HALFMASK;

    /**
     * Define the ChaCha20 state format
     */
    const STATE_CONST_LENGTH = 4;
    const STATE_CONST_BASEINDEX = 0;
    const STATE_KEY_LENGTH = 8;
    const STATE_KEY_BASEINDEX = 4;
    const STATE_COUNTER_LENGTH = 1;
    const STATE_COUNTER_BASEINDEX = 12;
    const STATE_NONCE_LENGTH = 3;
    const STATE_NONCE_BASEINDEX = 13;

    const STATE_ARRAY_LENGTH = self::STATE_CONST_LENGTH
        + self::STATE_KEY_LENGTH
        + self::STATE_COUNTER_LENGTH
        + self::STATE_NONCE_LENGTH;

    /**
     * Enum for state selection
     */
    const STATE_INITIAL = 0;
    const STATE_INTERMEDIATE = 1;
    const STATE_FINAL = 2;

    /**
     * These are the ChaCha20 constants. They are not magical,
     * nor cryptographically designed : the represent an ascii-str
     * "expand 32-byte k" when written as 4 LITTLE-endian uint32
     */
    const CONSTANT_VALUE_0 = 0x61707865; // "expa"
    const CONSTANT_VALUE_1 = 0x3320646e; // "nd 3"
    const CONSTANT_VALUE_2 = 0x79622d32; // "2-by"
    const CONSTANT_VALUE_3 = 0x6b206574; // "te k"

    /**
     * Number of full (column + diagonal) iterations
     */
    const FULL_QUARTER_ROUND_ITERATIONS = 10;

    /**
     * build a integer ensuring it stays an int on 32-bit platform
     *
     * MUST USE to construct any integer above 0x7FFFFFFF on 32-bit php
     */
    public static function buildUint32(int $hi, int $lo) {
        if ($hi < 0 or $hi > self::INT_BIT_HALFMASK) {
            throw new ChaCha20Exception(sprintf("Hi-part is outstide range [0..%d[", $hi, self::INT_BIT_HALFMASK));
        }
        if ($lo < 0 or $lo > self::INT_BIT_HALFMASK) {
            throw new ChaCha20Exception(sprintf("Lo-part is outstide range [0..%d[", $lo, self::INT_BIT_HALFMASK));
        }
        return $hi << self::INT_BIT_HALF_LENGTH | $lo;
    }

    /**
     * initial state is what is built when key, nonce, ctr are modified
     */
    private $initial_state;

    /**
     * intermediary state when rounds are done
     */
    private $intermediary_state;

    /**
     * final state is the output of the calculation
     */
    private $final_state;

    /**
     * ensures that every manipulated value is truncated to integer length
     *
     * @return uint32    an integer capped at INT_BIT_MASK bits
     */
    public static function cap(int $value) : int {
        return $value & self::INT_BIT_MASK;
    }

    /**
     * rotate bits to the left by $n bits
     *
     * @param uint32    $value      value to rotate
     * @param int       $left       number of slots to rotate
     *
     * @return uint32   $value rotated $nbits to the left
     */
    public static function rot_left(int $value, int $left) : int {
        if ($left < 0 or $left >= self::INT_BIT_LENGTH) {
            throw new ChaCha20Exception(sprintf("Left bitwise-rotation %d is outstide range [0..%d[", $left, self::INT_BIT_LENGTH));
        }
        if ($left === 0) {
            return $value;
        }
        $lp = self::cap($value << $left);
        $rp = self::cap($value >> (self::INT_BIT_LENGTH - $left));
        $m = (1 << $left) - 1;
        $value = $lp | ($rp & $m);
        return $value;
    }

    /**
     * does a bitwise XOR between the arguments
     *
     * @return uint32    an integer capped at INT_BIT_MASK bits
     */
    public static function xor(int $a, int $b) : int {
        return $a ^ $b;
    }

    /**
     * add two integers and cap the sum to the required number of bits
     * simulate half-length interger sum to avoid auto-conversions
     *
     * @return uint32    an integer capped at INT_BIT_MASK bits
     */
    public static function add_cap(int $a, int $b) : int {
        $ah = $a >> self::INT_BIT_HALF_LENGTH;
        $al = $a & self::INT_BIT_HALFMASK;
        $bh = $b >> self::INT_BIT_HALF_LENGTH;
        $bl = $b & self::INT_BIT_HALFMASK;
        $cl = $al + $bl;
        $cc = $cl >> self::INT_BIT_HALF_LENGTH;
        $cl &= self::INT_BIT_HALFMASK;
        $ch = $ah + $bh + $cc;
        $ch &= self::INT_BIT_HALFMASK;
        $c = self::buildUint32($ch, $cl);
        return $c;
    }

    /**
     * initialize initial state's "const" values one by one
     *
     * @param int       $index      index in const range
     * @param uint32    $value      value to store
     */
    public function set_const_index_value(int $index, int $value) {
        if ($index < 0 or $index >= self::STATE_CONST_LENGTH) {
            throw new ChaCha20Exception(sprintf("Const index %d is outstide range [0..%d[", $index, self::STATE_CONST_LENGTH.'['));
        }
        $this->initial_state[self::STATE_CONST_BASEINDEX + $index] = self::cap($value);
    }

    /**
     * initialize initial state's "key" values one by one
     *
     * @param int       $index      index in key range
     * @param uint32    $value      value to store
     */
    public function set_key_index_value(int $index, int $value) {
        if ($index < 0 or $index >= self::STATE_KEY_LENGTH) {
            throw new ChaCha20Exception(sprintf("Key index %d is outstide range [0..%d[", $index, self::STATE_KEY_LENGTH.'['));
        }
        $this->initial_state[self::STATE_KEY_BASEINDEX + $index] = self::cap($value);
    }

    /**
     * initialize initial state's "nonce" values one by one
     *
     * @param int       $index      index in nonce range
     * @param uint32    $value      value to store
     */
    public function set_nonce_index_value(int $index, int $value) {
        if ($index < 0 or $index >= self::STATE_NONCE_LENGTH) {
            throw new ChaCha20Exception(sprintf("Nonce index %d is outstide range [0..%d[", $index, self::STATE_NONCE_LENGTH.'['));
        }
        $this->initial_state[self::STATE_NONCE_BASEINDEX + $index] = self::cap($value);
    }

    /**
     * initialize initial state's "block-counter" index
     *
     * @param uint32    $position   new block-counter index
     */
    public function set_counter(int $position) {
        $this->initial_state[self::STATE_COUNTER_BASEINDEX] = self::cap($position);
    }

    /**
     * get "block-counter" index
     */
    public function get_counter() /* add ': int' in php 7.1 */ {
        return $this->initial_state[self::STATE_COUNTER_BASEINDEX];
    }

    /**
     * increment initial state's "block-counter" value by $step
     *
     * @param uint32    $step       step added to current block-counter value
     */
    public function inc_counter(int $step = 1) {
        $curval = $this->initial_state[self::STATE_COUNTER_BASEINDEX];

        if (PHP_INT_SIZE === 4)
        {
            $newval = self::add_cap($curval, $step);
            $overflowed = $curval < 0 and $newval > 0;
        } else {
            $newval = $curval + $step;
            $overflowed = $newval >> self::INT_BIT_LENGTH > 0;
        }

        if ($overflowed) {
            throw new ChaCha20Exception("Block-counter overloaded 32-bit capacity");
        }

        // set new counter
        $this->set_counter(self::cap($newval));
    }

    /**
     * puts binary data to INITIAL state
     *
     * extract $num little-endian uint32 from a least-significant-bit-starting
     * BINARY str named $name, and places these uint32's into INITIAL-state
     * starting at $index
     *
     * @param   binary_string     $str    binary string holding little-endian uint32's
     */
    public function bin_to_initial(string $str, string $name, int $index, int $num) {
        if ($index < 0) {
            throw new ChaCha20Exception(sprintf("Index %d cannot be negative", $index));
        }
        if ($num < 0) {
            throw new ChaCha20Exception(sprintf("Amount %d cannot be negative", $num));
        }
        if ($index + $num > self::STATE_ARRAY_LENGTH) {
            throw new ChaCha20Exception(sprintf("Cannot copy %d numbers starting at index %d as it would exceed target size of %d", $num, $index, self::STATE_ARRAY_LENGTH));
        }
        // check for input length
        $req_len = $num * self::INT_BIT_LENGTH >> 3;
        if (strlen($str) !== $req_len) {
            throw new ChaCha20Exception(sprintf('%s "%s" is not a %d-bits long hex string', $name, bin2hex($str), $req_len));
        }
        // extract littl-endian uint32 from it
        $arr = unpack("V".$num, $str);
        // place nonce uint32 into the state
        array_splice($this->initial_state, $index, $num, $arr);
    }

    /**
     * set key from a least-significant-bit-starting BINARY string
     */
    public function set_key(string $key_bin_string) {
        $this->bin_to_initial(
            $key_bin_string,
            "Key",
            self::STATE_KEY_BASEINDEX,
            self::STATE_KEY_LENGTH);
    }

    /**
     * set nonce from a least-significant-bit-starting BINARY string
     */
    public function set_nonce(string $nonce_bin_string) {
        $this->bin_to_initial(
            $nonce_bin_string,
            "Nonce",
            self::STATE_NONCE_BASEINDEX,
            self::STATE_NONCE_LENGTH);
    }

    /**
     * apply a quarter-round to a state
     *
     * @param int    $state      enum defining which state to return
     */
    public static function do_quarter_round(int $i_a, int $i_b, int $i_c, int $i_d, array &$state) {
        self::quarter_round($state[$i_a], $state[$i_b], $state[$i_c], $state[$i_d]);
    }

    /**
     * apply a quarter-round to FINAL al-state
     */
    public static function quarter_round(int &$a, int &$b, int &$c, int &$d) {
        // do the quarter round
        $a = self::add_cap($a, $b);  // a += b;
        $d = self::xor($d, $a);      // d ^= a;
        $d = self::rot_left($d, 16); // d <<<= 16;
        $c = self::add_cap($c, $d);  // c += d;
        $b = self::xor($b, $c);      // b ^= c;
        $b = self::rot_left($b, 12); // b <<<= 12;
        $a = self::add_cap($a, $b);  // a += b;
        $d = self::xor($d, $a);      // d ^= a;
        $d = self::rot_left($d, 8);  // d <<<= 8;
        $c = self::add_cap($c, $d);  // c += d;
        $b = self::xor($b, $c);      // b ^= c;
        $b = self::rot_left($b, 7);  // b <<<= 7;
    }

    /**
     * computes a block
     */
    public function compute_block() {
        // start from the initial state
        $this->intermediary_state = $this->initial_state;
        // compute full rounds
        for ($i=0; $i<self::FULL_QUARTER_ROUND_ITERATIONS; $i++) {
            // column rounds
            self::do_quarter_round(0, 4,  8, 12, $this->intermediary_state); // 1st column
            self::do_quarter_round(1, 5,  9, 13, $this->intermediary_state); // 2nd column
            self::do_quarter_round(2, 6, 10, 14, $this->intermediary_state); // 3rd column
            self::do_quarter_round(3, 7, 11, 15, $this->intermediary_state); // 4th column
            // diagonal rounds
            self::do_quarter_round(0, 5, 10, 15, $this->intermediary_state); // 1st diagonal
            self::do_quarter_round(1, 6, 11, 12, $this->intermediary_state); // 2nd diagonal
            self::do_quarter_round(2, 7,  8, 13, $this->intermediary_state); // 3rd diagonal
            self::do_quarter_round(3, 4,  9, 14, $this->intermediary_state); // 4th diagonal
        }
        // add the initial state to the final state
        for ($i=0; $i<self::STATE_ARRAY_LENGTH; $i++) {
            $this->final_state[$i] = self::add_cap(
                $this->intermediary_state[$i],
                $this->initial_state[$i]);
        }
    }

    /**
     * get internal state as an array of uint32
     *
     * @param int    $state      enum defining which state to return
     */
    public function get_state(int $state) {
        switch ($state) {
            case self::STATE_INITIAL:
                return $this->initial_state;
            case self::STATE_INTERMEDIATE:
                return $this->intermediary_state;
            case self::STATE_FINAL:
                return $this->final_state;
            default:
                throw new ChaCha20Exception(sprintf("State enum %d is invalid", $state));
        }
    }

    /**
     * set internal state as an array of uint32
     *
     * @param array  $array      array of uint32 to set as state
     * @param int    $state      enum defining which state to return
     */
    public function set_state(array $array, int $state) {
        switch ($state) {
            case self::STATE_INITIAL:
                $this->initial_state = $array;
                return;
            case self::STATE_INTERMEDIATE:
                $this->intermediary_state = $array;
                return;
            case self::STATE_FINAL:
                $this->final_state = $array;
                return;
            default:
                throw new ChaCha20Exception(sprintf("State enum %d is invalid", $state));
        }
    }

    /**
     * serialize internal state as binary string of little-endian uint32
     *
     * @param int    $state      enum defining which state to return
     */
    public function serialize_state(int $state) {
        $source = NULL;
        switch ($state) {
            case self::STATE_INITIAL:
                $source = $this->initial_state;
                break;
            case self::STATE_INTERMEDIATE:
                $source = $this->intermediary_state;
                break;
            case self::STATE_FINAL:
                $source = $this->final_state;
                break;
            default:
                throw new ChaCha20Exception(sprintf("State enum %d is invalid", $state));
        }
        return pack("V16", ...$source);
    }

    /**
     * construct a "NULL" Block
     *
     * creates and initalizes a Block.
     *
     * @param key   binary_string
     * @param nonce binary_string
     * @param ctr   uint32
     */
    public function __construct(string $key=NULL, string $nonce=NULL, int $ctr=NULL) {
        // empty everything
        $this->initial_state = array_fill(0, self::STATE_ARRAY_LENGTH, 0x00000000);
        $this->intermediary_state = $this->initial_state;
        $this->final_state = $this->initial_state;

        // initialize INITIAL state with algorithm constants
        $this->set_const_index_value(0, self::CONSTANT_VALUE_0);
        $this->set_const_index_value(1, self::CONSTANT_VALUE_1);
        $this->set_const_index_value(2, self::CONSTANT_VALUE_2);
        $this->set_const_index_value(3, self::CONSTANT_VALUE_3);

        // initialize others if provided
        if ($key !== NULL) {
            $this->set_key($key);
        }
        if ($nonce !== NULL) {
            $this->set_nonce($nonce);
        }
        if ($ctr !== NULL) {
            $this->set_counter($ctr);
        }
    }
}
