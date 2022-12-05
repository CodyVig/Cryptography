"""
Base class for RSA cryptosystem.
"""

import number_theory as nt


class RSA:

    # TO DO:
    # 1. Make a set_keys() method that sets the keys if the user does not
    #    supply keys themselves. (See MVElGamal.py)

    def __init__(self, b=1000):
        self._bit_size = b
        self._primes = self.__generate_rsa_primes(b)
        self.modulus = self._primes[0] * self._primes[1]
        self.encryption_exp = 0  # To be reassigned later.
        self.decryption_exp = 0  # To be reassigned later.

    def get_bit_size(self):
        """Returns the number of bits used to generate primes."""
        return self._bit_size

    def set_public_key(self, public_key=None):
        """
        Void method which sets self.modulus, self.encryption_exp.
        Call self.get_public_key to verify.

        Inputs:
        --- [optional] public_key = [N, e] : User-suplied public key.
        """

        if public_key is not None:
            # This means the user supplied their own key
            self.modulus = public_key[0]
            self.encryption_exp = public_key[1]
            return None

        # Create a key for the user
        self.encryption_exp = self.__generate_rsa_encryption_exp(
            self._primes[0], self._primes[1]
        )
        return None

    def set_private_key(self, private_key=None):
        """
        Void method which sets self.primes, self.decryption_exp.
        Call self.get_private_key to verify.

        Inputs:
        --- [optional] private_key = [N, d] : User-suplied private key.
        """

        if private_key is not None:
            # This means the user supplied their own key
            self.modulus = private_key[0]
            self.decryption_exp = private_key[1]
            return None

        # Create a key for the user
        self.decryption_exp = self.__generate_rsa_decryption_exp(
            self._primes[0], self._primes[1], self.encryption_exp
        )
        # del self.primes # Storing primes is a security flaw
        return None

    def get_public_key(self):
        """
        Returns [modulus, encryption_exponent]
        that is used by sender to encrypt messages.
        """

        return [self.modulus, self.encryption_exp]

    def get_private_key(self):
        """
        Returns [modulus, decryption_exponent]
        that is used by you to encrypt messages.
        """

        return [self.modulus, self.decryption_exp]

    def clear_security_flaws(self):
        """Call to delete self.primes after setting keys."""
        del self._primes
        return None

    def encrypt(self, message, pub_key):
        """
        Encrypts a plaintext message using RSA encryption.

        Inputs:
        message --- a string you wish to encrypt for transfer to third party.
        pub_key --- a list containing third party [N, e].

        Output:
        cipher --- the encrypted message to be given to recipient.
        """

        return nt.fast_power(nt.text_to_int(message), pub_key[1], pub_key[0])

    def decrypt(self, cipher):
        """
        Decrypts a ciphertext message using RSA decryption.

        Inputs:
        cipher  --- encrypted ciphertext received from sender.

        Output:
        message --- a string in English.
        """

        return nt.int_to_text(
            nt.fast_power(cipher, self.get_private_key()[1], self.get_private_key()[0])
        )

    def __generate_rsa_primes(self, b):
        """
        Generates two b-bit primes.
        """

        p = nt.find_prime(2**b, 2 ** (b + 1) - 1)
        q = nt.find_prime(2**b, 2 ** (b + 1) - 1)

        return [p, q]

    def __generate_rsa_encryption_exp(self, p, q):
        """
        Uses random number generation to produce
        a number coprime to (p-1)*(q-1).

        Inputs (two primes):
        --- p
        --- q

        Output:
        --- a number e such that gcd(e, (p-1)*(q-1)) = 1.
        """

        # Sage code used ZZ.random_element(). Is randint equivalent?
        from random import randint

        modulus = (p - 1) * (q - 1)

        while True:
            e = randint(2, modulus - 1)
            if nt.extended_gcd(e, modulus)[0] == 1:
                return e

    def __generate_rsa_decryption_exp(self, p, q, e):
        """
        Calculates the inverse of e mod (p-1)*(q-1).

        Inputs:
        --- p
        --- q
        --- e

        Output:
        --- d = the inverse of e modulo (p-1)*(q-1).
        """

        return nt.get_mod_inverse(e, (p - 1) * (q - 1))


if __name__ == "__main__":
    rsa = RSA(1000)

    # Generate keys for the user.
    rsa.set_public_key()
    rsa.set_private_key()
    rsa.clear_security_flaws()

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
