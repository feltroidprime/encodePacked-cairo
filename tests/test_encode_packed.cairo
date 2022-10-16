%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from lib.encodePacked import encode_packed
from starkware.cairo.common.alloc import alloc
@external
func __setup__() {
    %{
        def bin_c(u):
            b=bin(u)
            f = b[0:10] + ' ' + b[10:19] + '...' + b[-16:-8] + ' ' + b[-8:]
            return f

        def bin_64(u):
            b=bin(u)
            little = '0b'+b[2:][::-1]
            f='0b'+' '.join([b[2:][i:i+64] for i in range(0, len(b[2:]), 64)])
            return f
        def bin_8(u):
            b=bin(u)
            little = '0b'+b[2:][::-1]
            f="0b"+' '.join([little[2:][i:i+8] for i in range(0, len(little[2:]), 8)])
            return f

        def print_u_256_info(u, un):
            u = u.low + (u.high << 128) 
            print(f" {un}_{u.bit_length()}bits = {bin_c(u)}")
            print(f" {un} = {u}")
        def print_affine_info(p, pn):
            print(f"Affine Point {pn}")
            print_u_256_info(p.x, 'X')
            print_u_256_info(p.y, 'Y')

        def print_felt_info(u, un):
            print(f" {un}_{u.bit_length()}bits = {bin_8(u)}")
            print(f" {un} = {u}")
            # print(f" {un} = {int.to_bytes(u, 8, 'little')}")

        def print_u_512_info(u, un):
            u = u.d0 + (u.d1 << 128) + (u.d2<<256) + (u.d3<<384) 
            print(f" {un}_{u.bit_length()}bits = {bin_64(u)}")
            print(f" {un} = {u}")
        def print_u_512_info_u(l, h, un):
            u = l.low + (l.high << 128) + (h.low<<256) + (h.high<<384) 
            print(f" {un}_{u.bit_length()}bits = {bin_64(u)}")
            print(f" {un} = {u}")

        def print_u_256_neg(u, un):
            u = 2**256 - (u.low + (u.high << 128))
            print(f"-{un}_{u.bit_length()}bits = {bin_c(u)}")
            print(f"-{un} = {u}")

        def print_u256_array(address, len):
            for i in range(0, len):
                print(i)
                print_felt_info(memory[address+2*i] + (memory[address + 2*i+1] << 128), str(i))
        import bitarray, bitarray.util
        def encode_packed_256(address, len):
            b=bitarray.bitarray()
            for i in range(0,len):  
                b+=bitarray.util.int2ba(memory[address+2*i] + (memory[address + 2*i+1] << 128), endian='little')
            print(b)
    %}
    assert 1 = 1;
    return ();
}

@external
func test_packed2{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    alloc_locals;

    __setup__();
    let (x: Uint256*) = alloc();
    let x0 = Uint256(2 ** 128 - 1, 2 ** 128 - 1);
    assert x[0] = x0;
    assert x[1] = x0;
    let x_len = 2;

    let (x_i_bitlength: felt*) = alloc();
    assert x_i_bitlength[0] = 256;
    assert x_i_bitlength[1] = 256;

    let res: Uint256* = encode_packed.pack_u256_little(x, x_len, x_i_bitlength);
    %{ print_u256_array(ids.res.address_, 2) %}
    return ();
}

@external
func test_packed3{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    alloc_locals;

    __setup__();
    let (x: Uint256*) = alloc();
    let x0 = Uint256(2 ** 128 - 1, 2 ** 128 - 1);
    let x1 = Uint256(2 ** 128 - 1, 2 ** 127 - 1);

    assert x[0] = x1;
    assert x[1] = x0;
    assert x[2] = x0;

    let x_len = 3;

    let (x_i_bitlength: felt*) = alloc();
    assert x_i_bitlength[0] = 255;
    assert x_i_bitlength[1] = 256;
    assert x_i_bitlength[2] = 256;
    %{ print_u256_array(ids.x.address_, ids.x_len) %}
    %{ encode_packed_256(ids.x.address_, ids.x_len) %}

    let res: Uint256* = encode_packed.pack_u256_little(x, x_len, x_i_bitlength);
    %{ print_u256_array(ids.res.address_, ids.x_len) %}
    return ();
}

@external
func test_bit_length{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    alloc_locals;

    __setup__();

    let b = encode_packed.get_felt_bitlength(1002);
    assert b = 10;
    return ();
}

@external
func test_packed_auto{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    alloc_locals;

    __setup__();
    let (x: Uint256*) = alloc();
    let x0 = Uint256(
        161894476962632595678980058230621141717, 135594956203816336199041365895723851414
    );  // 255 b
    let x1 = Uint256(
        158652469219077549203721308731996547375, 37029641659475623520754783739314053225
    );  // 253 b
    let x2 = Uint256(
        288600309946081339912164709385528921233, 16924662596528861314676951345251986764
    );  // 252 b

    assert x[0] = x0;
    assert x[1] = x1;
    assert x[2] = x2;

    let x_len = 3;
    %{ print_u256_array(ids.x.address_, ids.x_len) %}
    %{ encode_packed_256(ids.x.address_, ids.x_len) %}

    let res: Uint256* = encode_packed.pack_u256_little_auto(x, x_len);
    %{ print_u256_array(ids.res.address_, ids.x_len) %}
    return ();
}
