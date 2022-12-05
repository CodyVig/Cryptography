"""
Base class for MV ElGamal crypotsystem.
"""

from random import randint
import number_theory as nt


class MVElGamal:

    # TO DO:
    # 1. Write code to take in a message `m` from the user, deduce whether or
    #    not that message is fewer than b bits, and decompose the message
    #    into [m1, m2] for MVElGamal encryption.
    # 2. Write tests for encryption and decryption.
    # 3. Add doc strings to all methods.

    def __init__(self, b=512):
        self._bit_size = b
        self._pub_params = [[0, 0], [0, 0], 0]
        self._public_key = [0, 0]
        self._private_key = 0

    def set_public_parameters(self, pub_params=None):

        if pub_params is not None:
            # The user supplied their own public parameters
            self._pub_params = pub_params
            return None
        # The user did not supply parameters, so we create them here.
        self._pub_params = self.__mv_parameter_creation(self._bit_size)
        return None

    def set_keys(self):
        """Call this method if you do not have keys of your own."""
        keys = self.__mv_key_creation(self._pub_params)
        self._private_key = keys[0]
        self._public_key = keys[1]
        return None

    def set_public_key(self, public_key):
        """Call this method if you have a public key of your own."""
        self._public_key = public_key
        return None

    def set_private_key(self, private_key):
        """Call this method if you have a private key of your own."""
        self._private_key = private_key
        return None

    def get_bit_size(self):
        return self._bit_size

    def get_public_parameters(self):
        return self._pub_params

    def get_public_key(self):
        return self._public_key

    def get_private_key(self):
        return self._private_key

    def encrypt(self, pub_params, m1, m2, public_key):
        """
        This follows the encryption algorithm discussed on page 365 of [HPS].
        """

        [E, P, p] = pub_params
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

    def decrypt(self, pub_params, cipher_text, private_key):

        [E, P, p] = pub_params
        [R, c1, c2] = cipher_text
        n = private_key

        # T = nR
        T = nt.double_and_add(R, n, E, p)
        [xt, yt] = T

        xt_inverse = nt.get_mod_inverse(xt, p)
        yt_inverse = nt.get_mod_inverse(yt, p)

        m1_prime = (xt_inverse * c1) % p
        m2_prime = (yt_inverse * c2) % p

        return [m1_prime, m2_prime]

    def __generate_elliptic_curve_and_point(self, p):

        while True:

            # Pick random point and random A.
            x0 = randint(0, p)
            y0 = randint(1, p)
            A = randint(1, p)

            # Now deduce what B must be.
            B = (y0**2 - x0**3 - A * x0) % p

            E = [A, B]
            P = [x0, y0]

            # Determine whether or not Delta = 0.
            if not nt.is_elliptic(E, p):
                continue
            else:
                return [E, P]

    def __mv_parameter_creation(self, b):

        # First create a prime of b bits.
        p = nt.find_prime(2 ** (b), 2 ** (b + 1))

        P = "O"
        while P == "O":
            # Generate the parameters
            [E, P] = self.__generate_elliptic_curve_and_point(p)

            # Make sure P has order > 2.
            if nt.add_points(P, P, E, p) == "O":
                P = "O"
            else:
                return [E, P, p]

    def __mv_key_creation(self, pub_params):

        [E, P, p] = pub_params

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
