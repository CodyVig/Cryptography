"""
Base class for MV ElGamal crypotsystem.
"""

from random import randint
import number_theory as nt


class MVElGamal:
    """
    An implementation of the Elliptic Curve MV ElGamal cryptosystem.

    :param bit_size: The number of bits in the primes which generate N.
    :type bit_size: int, optional, defaults to 512.
    :param public_parameters:
    :type public_parameters:
    :param public_key:
    :type public_key:
    :param private_key:
    :type private_key:
    """

    def __init__(
        self,
        bit_size: int = 512,
        public_parameters: list[int | list[int]] = None,
        public_key: list[int] = None,
        private_key: int = None,
    ):
        self._bit_size = bit_size
        if public_key is not None and private_key is not None:
            self.set_public_parameters(public_parameters)
            self.set_keys(public_key, private_key)
        elif public_key is not None or private_key is not None:
            raise ValueError(
                "Either both public_key and private_key must be specified, "
                + "or neither should be. You cannot pass only one."
            )
        else:
            self.__set_keys()

    def set_public_parameters(
        self, public_parameters: list[int | list[int]] = None
    ) -> list[int | list[int]]:
        """
        Sets (or generates) public parameters.

        :param public_parameters: A list [E, P, p] containing an elliptic curve
            E = [A, B], a point P = [X, Y] on E, and a prime p.
        :type public_parameters: list[list[int], list[int], int], optional.
            If not passed, the parameters are generated randomly.
        ::
        """

        if public_parameters is not None:
            # The user supplied their own public parameters
            self._public_parameters = public_parameters
            return None
        # The user did not supply parameters, so we create them here.
        self._public_parameters = self.__mv_parameter_creation(self._bit_size)
        return None

    def __set_keys(self) -> None:
        """Randomly generates a public and private key if none is supplied."""
        keys = self.__mv_key_creation(self._public_parameters)
        self._private_key: list[int] = keys[0]
        self._public_key: int = keys[1]
        return None

    def set_public_key(self, public_key: list[int]) -> None:
        """Sets `self.public_key` to user specified value."""
        self._public_key = public_key
        return None

    def set_private_key(self, private_key: int) -> None:
        """Sets `self.private_key` to user specified value."""
        self._private_key = private_key
        return None

    def get_bit_size(self) -> int:
        """
        Returns the number of bits used to generate `public_parameter` prime.
        """
        return self._bit_size

    def get_public_parameters(self) -> list[int | list[int]]:
        """
        Returns the number public parameters `[E, P, p]`.
        """
        return self._public_parameters

    def get_public_key(self) -> list[int]:
        """
        Returns the user's `public_key`.
        """
        return self._public_key

    def get_private_key(self) -> int:
        """
        Returns the user's `private_key`.
        """
        return self._private_key

    def encrypt(
        self,
        public_parameters: list[int | list[int]],
        message: str,
        public_key: list[int],
    ) -> list[int | list[int]]:
        """
        Encrypts a plaintext message using MV ElGamal encryption.

        :param public_parameters: the source's public paramters [E, P, p].
        :param message: a string you wish to encrypt.
        :param public_key: a list containing source's public key P = [X, Y].
        :return: the encrypted message to be given to source.
        """

        if ~self.__message_length_ok(message):
            raise ValueError("Your message is too long.")

        m1 = message[0 : len(message) // 2]
        m2 = message[len(message) // 2 : len(message)]

        [E, P, p] = public_parameters
        Q = public_key

        while True:
            # Choose a random k
            k = randint(2, p)

            # R = kP
            R = nt.double_and_add(P, k, E, p)

            # S = kQ
            S = nt.double_and_add(Q, k, E, p)

            if R == "O" or S == "O":
                continue
            else:
                [xs, ys] = S
                if xs == 0 or ys == 0:
                    continue
                else:

                    c1 = (xs * m1) % p
                    c2 = (ys * m2) % p

                    return [R, c1, c2]

    def decrypt(
        self,
        public_parameters: list[int | list[int]],
        cipher_text: list[int | list[int]],
    ) -> str:
        """
        Decrypts a ciphertext message using MV ElGamal decryption.

        :param public_parameters: the source's public paramters [E, P, p].
        :param cipher_text: encrypted ciphertext received from sender.
        :return: a string in English.
        """

        [E, P, p] = public_parameters
        [R, c1, c2] = cipher_text
        n = self._private_key

        T = nt.double_and_add(R, n, E, p)
        [xt, yt] = T

        xt_inverse = nt.get_mod_inverse(xt, p)
        yt_inverse = nt.get_mod_inverse(yt, p)

        m1_prime = (xt_inverse * c1) % p
        m2_prime = (yt_inverse * c2) % p

        return m1_prime + m2_prime

    def __message_length_ok(self, message: str) -> bool:
        """
        Checks to see if the message to be encrypted is fewer than b bits.\
        """

        return nt.text_to_int(message) < 2 ** (self._bit_size + 1) - 1

    def __generate_elliptic_curve_and_point(
        self, prime: int
    ) -> list[list[int]]:
        """
        Generates an elliptic curve E = [A, B] where y^2 = x^3 + Ax + B modulo
        `prime` together with a point P = [X, Y] on E. These are part of the
        public parameters.

        """

        while True:
            # Pick random point and random A.
            x0 = randint(0, prime)
            y0 = randint(1, prime)
            A = randint(1, prime)

            # Now deduce what B must be.
            B = (y0**2 - x0**3 - A * x0) % prime

            E = [A, B]
            P = [x0, y0]

            # Determine whether or not Delta = 0.
            if not nt.is_elliptic(E, prime):
                continue
            else:
                return [E, P]

    def __mv_parameter_creation(self, bit_size: int) -> list[int | list[int]]:
        """
        Generates `bit_size` bit public_parameters for MV ElGamal cryptosystem.
        """

        # First create a prime of b bits.
        p = nt.find_prime(2 ** (bit_size), 2 ** (bit_size + 1))

        P = "O"
        while P == "O":
            # Generate the parameters
            [E, P] = self.__generate_elliptic_curve_and_point(p)

            # Make sure P has order > 2.
            if nt.add_points(P, P, E, p) == "O":
                P = "O"
            else:
                return [E, P, p]

    def __mv_key_creation(
        self, public_parameters: list[int | list[int]]
    ) -> list[int | list[int]]:
        """
        Generates private key and public key for MV ElGamal cryptosystem.
        """

        [E, P, p] = public_parameters

        while True:
            # Choose a secret private_key (nA in notes):
            private_key = randint(2, p)

            # deduce the public_key:
            public_key = nt.double_and_add(P, private_key, E, p)

            # Make sure the public_key is useable!
            if public_key == "O" or public_key[1] == 0:
                continue
            else:
                return [private_key, public_key]


if __name__ == "__main__":
    mv_el_gamal = MVElGamal()

    # Generate parameters and keys for the user.
    mv_el_gamal.set_public_parameters()
    mv_el_gamal.set_keys()

    # Store the keys.
    pub_params = mv_el_gamal.get_public_parameters()
    prv_key = mv_el_gamal.get_private_key()
    pub_key = mv_el_gamal.get_public_key()

    print("The public parameters [E, P, p] are:")
    print(pub_params)
    print("\nYour public key is:")
    print(pub_key)
    print("\nYour private key is:")
    print(prv_key)
    print(
        "\nE = [A, B] encodes an elliptic curve y^2 = x^3 + Ax + B, "
        + "P = [x, y] is a point (x, y) on E, and p is a "
        + str(mv_el_gamal.get_bit_size())
        + "-bit prime number."
    )
    print(
        "\nYour public key is a point Q, not equal to P, "
        + "on the elliptic curve E. Your private key is an integer "
        + "n such that Q = nP via elliptic curve addition."
    )
    print("\nSave these numbers, and keep your private key hidden. ")
    print(
        "You can use these keys to encrypt and decrypt "
        + str(mv_el_gamal.get_bit_size())
        + "-bit messages to another user."
    )
