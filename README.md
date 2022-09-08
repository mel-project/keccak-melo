# Keccak.melo
This library implements the Keccak family of cryptographic hash functions in Themelio's covenant
language, Melodeon, including the original Keccak submission to the NIST competition (which is
still used by the Ethereum network), as well as the SHA-3 functions standardized by the NIST on
August 5, 2015.

## API
### The first six of the following interfaces belong to the SHA-3 family of cryptographic hash algorithms:

`shake128<$n, $o>(input: [U8; $n], output_len: {$o})`: Extendable output function (XOF) with 128 bits of security

`shake256<$n, $o>(input: [U8; $n], output_len: {$o})`: Extendable output function (XOF) with 256 bits of security

`sha3_224<$n>(input: [U8; $n])`: 28-byte output SHA-3 hashing function

`sha3_256<$n>(input: [U8; $n])`: 32-byte output SHA-3 hashing function

`sha3_384<$n>(input: [U8; $n])`: 48-byte output SHA-3 hashing function

`sha3_512<$n>(input: [U8; $n])`: 64-byte output SHA-3 hashing function

### The last four interfaces use the Keccak hashing algorithm as originally submitted to the NIST competition, before the padding changes:

`keccak224<$n>(input: [U8; $n])`: 28-byte output Keccak hashing function

`keccak256<$n>(input: [U8; $n])`: 32-byte output Keccak hashing function

`keccak384<$n>(input: [U8; $n])`: 48-byte output Keccak hashing function

`keccak512<$n>(input: [U8; $n])`: 64-byte output Keccak hashing function

## Building
To build and run this covenant, simply install Melodeon following the instructions in the
[guide](https://guide.melodeonlang.org/2_getting_started.html) and then `cd` into the folder
containing `keccak.melo` and run `melorun -i keccak.melo`. This will activate the Melodeon REPL and
will allow you to use the functions defined in this repo.

## Testing
There is a python file in this repo named `keccak.t.py` which is used to differentially fuzz test
the Melodeon implementation of Keccak with a reference implementation written in Python. Install
the dependencies using `python3.10 -m pip install colorama pexpect`, use the command
`python -i keccak.t.py` to load the program into an interactive Python REPL, and use the
`DIFFERENTIAL_TEST()` function to run this test.