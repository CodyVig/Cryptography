from random import randint

class MVElGamal:

    # TO DO: 
    # 1. Write code to take in a message m from the user, deduce whether or
    #    not that message is fewer than b bits, and decompose the message
    #    into [m1, m2] for MVElGamal encryption.
    # 2. Write tests for encryption and decryption.
    # 3. Add doc strings to all methods.

    def __init__(self, b = 512):
        self._bit_size = b
        self._pub_params = [[0, 0], [0, 0], 0]
        self._public_key = [0, 0]
        self._private_key = 0

    def set_public_parameters(self, pub_params = None):
        
        if (pub_params is not None):
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
            R = self.__double_and_add(P, k, E, p)

            # S = kQ
            S = self.__double_and_add(Q, k, E, p)

            if(R == "O" or S == "O"):
                continue
            else:
                [xs, ys] = S
                if(xs == 0 or ys == 0):
                    continue
                else:

                    c1 = (xs * m1) % p
                    c2 = (ys * m2) % p

                    return [R, c1, c2]

    def decrypt(self, pub_params, cipher_text, private_key):

        [E, P, p]   = pub_params
        [R, c1, c2] = cipher_text
        n = private_key

        # T = nR
        T = self.__double_and_add(R, n, E, p)
        [xt, yt] = T

        xt_inverse = self.__get_mod_inverse(xt, p)
        yt_inverse = self.__get_mod_inverse(yt, p)

        m1_prime = (xt_inverse * c1) % p
        m2_prime = (yt_inverse * c2) % p

        return [m1_prime, m2_prime]
    
    ##
    ## Requisite number theory code.
    ##

    def __division_with_remainder(self, a, b):
        """Long divides a/b to get [q, r] such that a = bq + r"""
        return [a//b, a%b]


    def __extended_gcd(self, a, b):
        """
        Runs extended Euclidean algorithm on inputs (a, b) to find [g, u, v] 
        such that g = gcd(a, b) and au + bv = g. This follows the algorithm 
        introduced in Problem 1.12 of Hoffstein, et al.
        """

        u = 1; g = a; x = 0; y = b

        while(y != 0):
            [q, t] = self.__division_with_remainder(g, y)
            s = u - q*x
            u = x; g = y; x = s; y = t

        v = (g - a*u) // b
        return [g, u, v]

    def __get_mod_inverse(self, a, p):
        """Returns the inverse of a mod p"""

        [g, u, v] = self.__extended_gcd(a, p)

        if (g != 1):
            raise ValueError(
                "The arguments of get_mod_inverse are not coprime!")

        return u % p

    def __get_binary(self, A):
        """
        Returns the coefficients [A0, ..., Ar] 
        such that A = A0*2^0 + ... + A_r*2^r
        """

        x = A
        i = 0
        binary_rep = []

        while(x != 0):
            [q, r] = self.__division_with_remainder(x, 2)
            binary_rep.append(r)
            x = q
            if(x == 0):
                return binary_rep
            i += 1

    def __fast_power(self, g, A, N):
        """Returns g^A (mod N) using the algorithm in HW 2 Problem 2(b)."""

        # If exponent is negative, replace g with the inverse of g
        if (A < 0):
            g = self.__get_mod_inverse(g, N)
            A = -A

        a = g
        b = 1

        while(A > 0):
            if(A%2 == 1):
                b = (b*a) % N

            a = a**2 % N ; A = A//2

        return b

    ##
    ## ASCII functions.
    ##

    def __text_to_int(self, w):
        """
        Takes in a string and outputs an integer 
        satisfying the above equation.
        """

        n = 0

        for i in range(len(w)):
            n += ord(w[i]) * 256**i

        return n

    def __int_to_text(self, n):
        """
        Takes in an integer and returns its corresponding string using
        the ASCII dictionary without storing the base-256 expansion.
        """

        text = ""
        x = n; i = 0

        while(x != 0):
            [x, r] = self.__division_with_remainder(x, 256)
            text += chr(r)
            if(x == 0):
                return text
            i += 1

    ##
    ## Elliptic Curve functions.
    ##

    def __is_elliptic(self, E, p):
        [A, B] = E

        if((4*A**3 + 27*B**2)%p == 0):
            return False
        else:
            return True

    def __on_curve(self, P, E, p):

        # Check if P is the point at infinity
        if (P == 'O'):
            # 'O' is only on *elliptic* curves
            if self.__is_elliptic(E, p):
                return True
            else:
                return False

        [A, B] = E
        [X, Y] = P

        LHS = Y**2
        RHS = X**3 + A*X + B

        if (LHS %p == RHS %p):
            return True
        else:
            return False

    def __add_points(self, P, Q, E, p):
        """
        Adds two points on an elliptic curve. 
        (If one of the points is O, input as +Infinity)

        Inputs:
        --- E: [a, b], coefficients of elliptic curve y^2 = x^3 + ax + b;
        --- P: a point on E;
        --- Q: a point on E;
        --- p: a prime > 2.

        Output:
        --- The point P + Q on E.
        """

        # Are these points on the curve?
        if (self.__on_curve(P, E, p) == False):
            raise ValueError("First argument " 
                + str(P) + " is not a point on E.")
        if (self.__on_curve(Q, E, p) == False):
            raise ValueError("Second argument " 
                + str(Q) + " is not a point on E.")

        O = 'O'

        # Is P or Q the point at infinity?
        if (P == O):
            return Q
        if (Q == O):
            return P

        [a, b] = E
        [x1, y1] = P
        [x2, y2] = Q

        # Reduce the inputs mod p, just in case.
        x1 = x1%p
        x2 = x2%p
        y1 = y1%p
        y2 = y2%p

        # Implement the algorithm from class.
        if(x1 == x2 and y1 == (p-y2)%p):
            return O
        else:
            if (x1 != x2):
                L = self.__get_mod_inverse((x2 - x1), p) * (y2 - y1)
            else:
                L = self.__get_mod_inverse(2*y1, p) * (3*x1**2 + a)

        L = L%p
        x3 = L**2 - x1 - x2
        y3 = L * (x1 - x3) - y1

        return [x3%p, y3%p]

    def __double_and_add(self, P, n, E, p):

        a = P
        nP = 'O'

        while(n > 0):
            if(n%2 == 1):
                nP = self.__add_points(nP, a, E, p)

            a = self.__add_points(a, a, E, p)
            n = n//2

        return nP

    ##
    ## Prime number functions.
    ##

    def __miller_rabin(self, a, n):
        """If a is a Miller-Rabin witness for n, return true. Else, false."""

        # False == Potentially prime
        # True  == Miller-Rabin Witness -> Definitely composite

        # Write n-1 = 2^k * q where q is odd.
        k = 0
        q = n-1
        while (q%2 == 0):
            k += 1
            q = q//2

        x = self.__fast_power(a, q, n)

        # Is a^m = 1 mod n? Then a is not a witness
        if (x == 1):
            return False

        power_of_x = x
        for i in range(k):
            # Is this p-1 mod n? If so, not a witness
            if (power_of_x == n-1):
                return False
            power_of_x = (power_of_x**2) % n

        # If we've made it here, the number is a witness.
        return True

    def __probably_prime(self, n):
        number_of_checks = 20
        for i in range(number_of_checks):
            x = randint(2, n-1)
            witness = self.__miller_rabin(x, n)

            # Is x a witness? If so, n is definitely composite.
            if (witness == True):
                return False

        # If we made it here, then none of the random numbers were witnesses
        return True

    def __find_prime(self, lowerBound, upperBound):
        """Uses probably_prime and a random.randint to produce a prime.

        Inputs:
        --- lowerBound
        --- upperBound

        Output:
        --- a number p between lowerBound and upperBound 
            which is very likely to be prime."""

        while True:
            potential_prime = randint(lowerBound, upperBound)
            if self.__probably_prime(potential_prime):
                return potential_prime
            
    ##          
    ## ElGamal code.
    ##

    def __generate_elliptic_curve_and_point(self, p):

        while True:

            # Pick random point and random A.
            x0 = randint(0, p)
            y0 = randint(1, p)
            A  = randint(1, p)

            # Now deduce what B must be.
            B  = (y0**2 - x0**3 - A*x0) % p

            E = [A, B]
            P = [x0, y0]

            # Determine whether or not Delta = 0.
            if (not self.__is_elliptic(E, p)):
                continue
            else:
                return [E, P]

    def __mv_parameter_creation(self, b):

        # First create a prime of b bits.
        p = self.__find_prime(2**(b), 2**(b+1))

        P = 'O'
        while (P == 'O'):
            # Generate the parameters
            [E, P] = self.__generate_elliptic_curve_and_point(p)

            # Make sure P has order > 2.
            if (self.__add_points(P, P, E, p) == 'O'):
                P = 'O'
            else:
                return [E, P, p]

    def __mv_key_creation(self, pub_params):

        [E, P, p] = pub_params

        while True:
            # Choose a secret private_key (nA in notes):
            private_key = randint(2, p)

            # deduce the public_key:
            public_key = self.__double_and_add(P, private_key, E, p)

            # Make sure the public_key is useable!
            if(public_key == 'O' or public_key[1] == 0):
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
    print("\nE = [A, B] encodes an elliptic curve y^2 = x^3 + Ax + B, "
        + "P = [x, y] is a point (x, y) on E, and p is a "
        + str(mv_el_gamal.get_bit_size()) + "-bit prime number.")
    print("\nYour public key is a point Q, not equal to P, "
        + "on the elliptic curve E. Your private key is an integer "
        + "n such that Q = nP via elliptic curve addition.")
    print("\nSave these numbers, and keep your private key hidden. ")
    print("You can use these keys to encrypt and decrypt " 
        + str(mv_el_gamal.get_bit_size()) + "-bit messages to another user.")