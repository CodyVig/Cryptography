# Cryptography
An object-oriented representation of some classic cryptosystems.

## [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
To initialize an RSA cryptosystem, use:
```python
rsa_implementation = RSA(bit_size: int = 1000, keys: list[int] = None)
```
`bit_size` is the number of bits of your primes $p$ and $q$. That is, the bit_size $b$ is such that $$2^{b} \leq p, q \leq 2^{b+1}-1.$$ `keys = [public_key, private_key]` contains your personal public key and private key, where `public_key = [N: int, e: int]` is the public modulus and encryption exponent and `private_key = [N: int, d: int]` is the public modulus and decryption exponent. If `keys` is not specified, keys will be generated for you upon instantiation.

To encrypt a message, find your source's public key, then use:
```python
cipher_text = rsa_implementation.encrypt(message: str, source_public_key: list[int])
```
Send to the source your cipher text.

To decrypt a message sent to you by a source, use:
```python
message = rsa_implementation.decrypt(source_cipher: int)
```


## MV ElGamal
The Menezes–Vanstone ElGamal cryptosystem is an implementation of a Diffie-Hellman key exchange with ElGamal encryption and decryption over an elliptic curve group mod $p$.

Documentation to-be-updated.

## Notes
This code was adapted from code written for Math 116 at UC Berkeley, taken in Fall 2021 with Professor Gabriel Dorfsman-Hopkins.
