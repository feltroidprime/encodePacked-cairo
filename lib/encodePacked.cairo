from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_reverse_endian,
    uint256_unsigned_div_rem,
    uint256_mul,
    uint256_add,
    uint256_pow2,
)
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
        encode_packed_u256_bits_loop(
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

        if (is_le(bit_len_next, shifted_bits_sum + (256 - bit_len)) == 1) {
            // Not implemented / tested
            // Next word length is smalller than the number of bits to be shifted.*
            %{ print('Encode packed special case') %}
            return encode_packed_u256_bits_loop(
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

            return encode_packed_u256_bits_loop(
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
            return encode_packed_u256_bits_loop(
                x, x_len, x_i_bitlength, index + 1, res, shifted_bits_sum, x[index + 1]
            );
        }
        return res;
    }
}
