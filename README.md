# Cryptography
**This repo is under active development.**

An object-oriented representation of some classic cryptosystems.

## [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
To initialize an RSA cryptosystem, use:
```python
rsa_implementation = RSA(bit_size: int = 1000, keys: list[int] = None)
```

* `bit_size: int` is the number of bits of your primes $p$ and $q$. That is, the bit size $b$ is such that $2^{b} \leq p, q \leq 2^{b+1}-1$.
* `keys = [public_key: list[int], private_key: list[int]]` contains your personal public key and private key.
  * `public_key = [N: int, e: int]` is your public modulus and encryption exponent.
  * `private_key = [N: int, d: int]` is your public modulus and decryption exponent.

If `keys` is not specified, keys will be generated for you upon instantiation.

To encrypt a message, find your source's public key, then use:
```python
cipher_text = rsa_implementation.encrypt(message: str, source_public_key: list[int])
```
You may then safely send this cipher text to your source.

To decrypt a message sent to you by a source, use:
```python
message = rsa_implementation.decrypt(source_cipher: int)
```


## MV ElGamal
The Menezes–Vanstone ElGamal cryptosystem is an implementation of a Diffie-Hellman key exchange with ElGamal encryption and decryption over an elliptic curve group mod $p$.

To initialize an ElGamal cryptosystem, use:
```python
elgamal_implementation = MVElGamal(
    bit_size: int = 512, 
    public_parameters: list[int | list[int]] = None,
    public_key: list[int] = None,
    private_key: int = None
)
```

* `bit_size: int` is the number of bits of your prime $p$. That is, the bit size $b$ is such that $2^{b} \leq p \leq 2^{b+1}-1$.
* `public_parameters = [E: list[int], P: list[int], p: int]` contains the following: 
    * the elliptic curve `E = [A, B]` where $y^2 = x^3 + Ax + B$, 
    * a point `P = [x, y]` on `E`, and 
    * the prime `p` over which the elliptic curve is defined. 
* `public_key = [x: int, y: int]` is a multiple of the public parameter `P`.
* `private_key: int` is the integer $n$ for which the public key is $nP$.

If the parameters and/or keys are not specified, they will be generated for you upon instantiation.

To encrypt a message, find your source's public parameters and public key, then use:
```python
cipher_text = elgamal_implementation.encrypt(
    message: str,
    source_public_parameters: list[int | list[int]],
    source_public_key: list[int]
)
```
You may then safely send this cipher text to your source.

To decrypt a message sent to you by a source, use:
```python
message = elgamal_implementation.decrypt(source_cipher: int)
```



## Notes
This code was adapted from code written for Math 116 at UC Berkeley, taken in Fall 2021 with Professor Gabriel Dorfsman-Hopkins.
