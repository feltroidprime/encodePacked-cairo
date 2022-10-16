from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_reverse_endian,
    uint256_unsigned_div_rem,
    uint256_mul,
    uint256_add,
    uint256_pow2,
)
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.math import unsigned_div_rem as felt_divmod, split_felt
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.pow import pow

namespace encode_packed {
    func pack_u256_little{range_check_ptr}(
        x: Uint256*, x_len: felt, x_i_bitlength: felt*
    ) -> Uint256* {
        alloc_locals;
        let (res: Uint256*) = alloc();
        let res_start = res;
        encode_packed_u256_little_loop(
            x=x,
            x_len=x_len,
            x_i_bitlength=x_i_bitlength,
            index=0,
            res=res_start,
            shifted_bits_sum=0,
            temp_next=x[1],
        );
        return res_start;
    }
    func pack_u256_little_auto{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        x: Uint256*, x_len: felt
    ) -> Uint256* {
        alloc_locals;
        let (res: Uint256*) = alloc();
        let res_start = res;
        let (x_i_bitlength: felt*) = alloc();

        get_u256_bitlength_loop(x, x_len, x_i_bitlength, 0);

        encode_packed_u256_little_loop(
            x=x,
            x_len=x_len,
            x_i_bitlength=x_i_bitlength,
            index=0,
            res=res_start,
            shifted_bits_sum=0,
            temp_next=x[1],
        );
        return res_start;
    }

    func get_felt_bitlength{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(x: felt) -> felt {
        alloc_locals;
        local bit_length;
        %{
            x = ids.x
            ids.bit_length = x.bit_length()
        %}

        let le = is_le(bit_length, 252);
        assert le = 1;
        assert bitwise_ptr[0].x = x;
        let (n) = pow(2, bit_length);
        assert bitwise_ptr[0].y = n - 1;
        tempvar word = bitwise_ptr[0].x_and_y;
        assert word = x;

        assert bitwise_ptr[1].x = x;

        let (n) = pow(2, bit_length - 1);

        assert bitwise_ptr[1].y = n - 1;
        tempvar word = bitwise_ptr[1].x_and_y;
        assert word = x - n;

        let bitwise_ptr = bitwise_ptr + 2 * BitwiseBuiltin.SIZE;
        return bit_length;
    }
    func get_u256_bitlength{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(x: Uint256) -> felt {
        alloc_locals;
        let b2 = get_felt_bitlength(x.high);
        if (b2 != 0) {
            return 128 + b2;
        } else {
            let b1 = get_felt_bitlength(x.low);
            return b1 + b2;
        }
    }
    func get_u256_bitlength_loop{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        x: Uint256*, x_len: felt, x_i_bitlength: felt*, index: felt
    ) {
        if (index == x_len) {
            return ();
        }
        let b = get_u256_bitlength(x[index]);
        assert x_i_bitlength[index] = b;
        return get_u256_bitlength_loop(x, x_len, x_i_bitlength, index + 1);
    }
    func cut_missing_bits_from_next_little{range_check_ptr}(
        n_bits: felt, x_next: Uint256, shifted_bits_sum: felt
    ) -> (left_bits: Uint256, right_bits: Uint256) {
        // Not zero from encode_packed_u256_loop
        alloc_locals;

        let (power) = uint256_pow2(Uint256(shifted_bits_sum + 256 - n_bits, 0));
        let (q: Uint256, r: Uint256) = uint256_unsigned_div_rem(x_next, power);
        %{
            print('r')
            print_u256_array(ids.r.address_, 1)
        %}

        let (power) = uint256_pow2(Uint256(n_bits, 0));

        let (m_r_low: Uint256, _) = uint256_mul(r, power);

        return (left_bits=m_r_low, right_bits=q);
    }
    func encode_packed_u256_little_loop{range_check_ptr}(
        x: Uint256*,
        x_len: felt,
        x_i_bitlength: felt*,
        index: felt,
        res: Uint256*,
        shifted_bits_sum: felt,
        temp_next: Uint256,
    ) -> Uint256* {
        alloc_locals;
        %{ print("Encode Packed index : ", ids.index) %}

        if (index == x_len - 1) {
            %{ print('end of loop') %}
            assert res[index] = temp_next;
            return res;
        }

        let bit_len = x_i_bitlength[index];
        let bit_len_next = x_i_bitlength[index + 1];
        %{ print("Bitlen : ", ids.bit_len) %}

        if (is_le(bit_len_next, shifted_bits_sum + (256 - bit_len)) == 1) {
            // Not implemented / tested
            // Next word length is smalller than the number of bits to be shifted.*
            %{ print('Encode packed special case') %}
            return encode_packed_u256_little_loop(
                x,
                x_len,
                x_i_bitlength,
                index + 1,
                res,
                shifted_bits_sum + (256 - bit_len) - bit_len_next,
                temp_next,
            );
        }
        if (is_le(bit_len - shifted_bits_sum, 255) == 1) {
            %{ print('Encode packed Uint is lower than 256bits') %}
            %{ print("Shifted bit sum :", ids.shifted_bits_sum) %}
            let (left_bits: Uint256, right_bits: Uint256) = cut_missing_bits_from_next_little(
                bit_len, temp_next, shifted_bits_sum
            );
            %{ print_u256_array(ids.left_bits.address_, 1) %}
            %{ print_u256_array(ids.right_bits.address_, 1) %}

            let (m_low, _) = uint256_add(x[index], left_bits);

            assert res[index] = m_low;

            return encode_packed_u256_little_loop(
                x,
                x_len,
                x_i_bitlength,
                index + 1,
                res,
                shifted_bits_sum + (256 - bit_len),
                right_bits,
            );
        }
        if (bit_len - shifted_bits_sum == 256) {
            %{ print('last case') %}
            assert res[index] = temp_next;
            return encode_packed_u256_little_loop(
                x, x_len, x_i_bitlength, index + 1, res, shifted_bits_sum, x[index + 1]
            );
        }
        return res;
    }
}
