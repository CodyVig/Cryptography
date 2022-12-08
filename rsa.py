"""
Base class for RSA cryptosystem.
"""

from random import randint
import number_theory as nt


class RSA:
    """
    An implementation of the RSA cryptosystem.

    :param bit_size: The number of bits in the primes which generate N.
    :type bit_size: int, optional, defaults to 1000.
    :param keys: A list containing public key, private key.
    :type keys: list[list[int]], optional, default randomly generated.
    """

    def __init__(self, bit_size: int = 1000, keys: list[list[int]] = None):
        self._bit_size = bit_size
        self.encryption_exp: int = 0  # To be reassigned later.
        self.decryption_exp: int = 0  # To be reassigned later.
        if keys is not None:
            self.reset_public_key(keys[0])
            self.reset_private_key(keys[1])
            self.__clear_security_flaws()
        else:
            self._primes: list[int] = self.__generate_rsa_primes(bit_size)
            self.modulus: int = self._primes[0] * self._primes[1]
            self.reset_public_key()
            self.reset_private_key()
            self.__clear_security_flaws()

    def get_bit_size(self) -> int:
        """Returns the number of bits used to generate primes."""
        return self._bit_size

    def reset_public_key(self, public_key: list[int] = None) -> None:
        """
        Void method which sets `self.modulus`, `self.encryption_exp`.
        Call `self.get_public_key` to verify.

        :param public_key: [N, e], the user-suplied public key.
        """

        if public_key is not None:
            self.modulus = public_key[0]
            self.encryption_exp = public_key[1]
            return None

        self.encryption_exp = self.__generate_rsa_encryption_exp(
            self._primes[0], self._primes[1]
        )
        return None

    def reset_private_key(self, private_key: list[int] = None) -> None:
        """
        Void method which sets `self.primes`, `self.decryption_exp`.
        Call `self.get_private_key` to verify.

        :param private_key: [N, d], the user-suplied private key.
        :type private_key: list[int], optional.
        """

        if private_key is not None:
            self.modulus = private_key[0]
            self.decryption_exp = private_key[1]
            return None

        self.decryption_exp = self.__generate_rsa_decryption_exp(
            self._primes[0], self._primes[1], self.encryption_exp
        )
        return None

    def get_public_key(self) -> list[int]:
        """
        Returns `[self.modulus, self.encryption_exp]`
        that is used by sender to encrypt messages.
        """

        return [self.modulus, self.encryption_exp]

    def get_private_key(self) -> list[int]:
        """
        Returns `[self.modulus, self.decryption_exp]`
        that is used by user to encrypt messages.
        """

        return [self.modulus, self.decryption_exp]

    def encrypt(self, message: str, pub_key: list[int]) -> int:
        """
        Encrypts a plaintext message using RSA encryption.

        :param message: a string you wish to encrypt.
        :param pub_key: a list containing third party `[N, e]`.
        :return: the encrypted message to be given to recipient.
        """

        return nt.fast_power(nt.text_to_int(message), pub_key[1], pub_key[0])

    def decrypt(self, cipher: int) -> str:
        """
        Decrypts a ciphertext message using RSA decryption.

        :param cipher: encrypted ciphertext received from sender.
        :return: a string in English.
        """

        return nt.int_to_text(
            nt.fast_power(
                cipher, self.get_private_key()[1], self.get_private_key()[0]
            )
        )

    def __clear_security_flaws(self) -> None:
        """Call to delete `self.primes` after setting keys."""
        del self._primes
        return None

    def __generate_rsa_primes(self, bit_size: int) -> list[int]:
        """
        Generates two b-bit primes.

        :param bit_size: the number of bits the primes should be.
        :return: two distinct b-bit primes.
        """

        p = nt.find_prime(2**bit_size, 2 ** (bit_size + 1) - 1)
        q = p
        while q == p:
            q = nt.find_prime(2**bit_size, 2 ** (bit_size + 1) - 1)

        return [p, q]

    def __generate_rsa_encryption_exp(self, p: int, q: int) -> int:
        """
        Uses random number generation to produce
        a number coprime to (p-1) * (q-1).

        :param p: A prime
        :param q: A prime
        :return: A number coprime to (p-1) * (q-1).
        """

        modulus = (p - 1) * (q - 1)

        while True:
            e = randint(2, modulus - 1)
            if nt.extended_gcd(e, modulus)[0] == 1:
                return e

    def __generate_rsa_decryption_exp(self, p: int, q: int, e: int) -> int:
        """
        Calculates the inverse of e mod (p-1) * (q-1).

        :param p: A prime
        :param q: A prime
        :param e: A number coprime to (p-1) * (q-1).
        :return: the inverse of e modulo (p-1) * (q-1).
        """

        return nt.get_mod_inverse(e, (p - 1) * (q - 1))


if __name__ == "__main__":
    rsa = RSA(1000)

    # Store the keys.
    prv_key = rsa.get_private_key()
    pub_key = rsa.get_public_key()

    print("Your public key [N, e] is:")
    print(pub_key)
    print("\nYour private key [N, d] is:")
    print(prv_key)
    print("\nSave these numbers, and keep your private key hidden. ")
    print(
        "You can use these keys to encrypt and decrypt "
        + str(rsa.get_bit_size())
        + "-bit messages to another user."
    )
