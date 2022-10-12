# encodePacked-cairo
## Concatenate values without padding to prepare input for hash functions such as keccak.



> ## ⚠️ alpha version Code ! ⚠️
>
> Expect rapid iteration and support for little/big endian values, further gas optimisations and more documentation and examples. 
> 

## - Setup for development  
Install Protostar. Clone the repository. Use python 3.9.

```bash
python3.9 -m venv venv
source venv/bin/activate
pip install -r requirements.txte
```

Run tests :

```
protostar test tests/
```

You may need to use `protostar test --disable-hint-validation`  if hints are used in the library.

## - Pack your values without padding 

Use the library in lib/encodePacked.cairo and import its namespace :
```
from lib.encodePacked import encode_packed
```
### 1. Pack without padding a little-endian Uint256 array
```
encode_packed.pack_u256_little(x, x_len, x_i_bitlength);

```
Inputs : 

- x : Uint256*, array of Uint256 values
- x_len : felt, the nunmber of elements in the array
- x_i_bitlength: felt*, array of felts, to declare the number of bits in each element

Returns : 

 - Uint256* : array packed without padding 

### 2. Pack without padding a big-endian Uint256 array

[Not implemented]


## - Use the results as input for keccak hash