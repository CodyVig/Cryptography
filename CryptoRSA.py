class RSA:
    # __init__ runs upon instantiation and stores these attributes permanently 
    # for each object.
    def __init__(self, b = 1000):
        self._bit_size = b
        self._primes = self.__generate_rsa_primes(b)
        
    def get_bit_size(self):
        """Returns the number of bits used to generate primes."""
        return self._bit_size
    
    def set_public_key(self, public_key = None):
        """
        Void method which sets self.modulus, self.encryption_exp. 
        Call self.get_public_key to verify.

        Inputs:
        --- [optional] public_key = [N, e] : User-suplied public key.
        """

        if (public_key is not None):
            # This means the user supplied their own key
            self.modulus = public_key[0]
            self.encryption_exp = public_key[1]
            return None

        # Create a key for the user
        self.modulus = self._primes[0] * self._primes[1]
        self.encryption_exp = self.__generate_rsa_encryption_exp(
            self._primes[0], self._primes[1])
        return None

    def set_private_key(self, private_key = None):
        """
        Void method which sets self.primes, self.decryption_exp. 
        Call self.get_private_key to verify.

        Inputs:
        --- [optional] private_key = [N, d] : User-suplied private key.
        """

        if (private_key is not None):
            # This means the user supplied their own key
            self.modulus = private_key[0]
            self.decryption_exp = private_key[1]
            return None

        # Create a key for the user
        self.modulus = self._primes[0] * self._primes[1]
        self.decryption_exp = self.__generate_rsa_decryption_exp(
            self._primes[0], self._primes[1], self.encryption_exp)
        #del self.primes # Storing primes is a security flaw
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
    
        return self.__fast_power(self.__text_to_int(message), 
                                       pub_key[1], 
                                       pub_key[0])

    def decrypt(self, cipher):
        """
        Decrypts a ciphertext message using RSA decryption.
        
        Inputs:
        cipher  --- encrypted ciphertext received from sender.
        
        Output:
        message --- a string in English.
        """
    
        return self.__int_to_text(self.__fast_power(
            cipher, 
            self.get_private_key()[1], 
            self.get_private_key()[0]))
    
    # The following functions are needed to perform number-theoretic 
    # calculations to encrypt and decrypt.
    def __division_with_remainder(self, a, b):
        """Long divides a/b to get [q, r] such that a = bq + r"""
        return [(a - a%b)//b, a%b]
    
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
        """
        Returns the inverse of a mod p.
        """
    
        [g, u, v] = self.__extended_gcd(a, p)
    
        if (g != 1):
            raise ValueError("The arguments of getModInverse are not coprime!")
    
        return u % p

    def __fast_power(self, g, A, N):
        """
        Returns g^A (mod N) using a low-space 
        and low-time complexity algorithm.
        """
    
        # If exponent is negative, replace g with the inverse of g
        if (A < 0):
            g = self.__get_mod_inverse(self, g, N)
            A = -A
    
        a = g; b = 1
    
        while(A > 0):
            if(A%2 == 1):
                b = (b*a) % N
    
            a = a**2 % N ; A = A//2
    
        return b
    
    def __text_to_int(self, w):
        """
        Takes in a string and outputs an integer satisfying the above equation.
        """
        n = 0
        for i in range(len(w)):
            n += ord(w[i]) * 256**i
        return n


    def __int_to_text(self, n):
        """
        Takes in an integer and returns its corresponding string using the 
        ASCII dictionary without storing the base-256 expansion.
        """
    
        text = ""
        x = n; i = 0
    
        while(x != 0):
            [x, r] = self.__division_with_remainder(x, 256)
            text = text + chr(r)
            if(x == 0):
                return text
            i += 1
            
    def __miller_rabin(self, a, n):
        """
        If a is a Miller-Rabin witness for n, return true. Else, false.
        """
    
        # False == Potentially prime
        # True  == Miller-Rabin Witness ---> Definitely composite
    
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
            # Is this -1 ---> p-1 mod n? If so, not a witness
            if (power_of_x == n-1):
                return False
            power_of_x = (power_of_x**2) % n
    
        # If we've made it here, the number is a witness.
        return True
    
    def __probably_prime(self, n):
        """
        Uses Miller-Rabin Witness test a fixed number of times to 
        probablistically determine whether or not input is prime.
        """
        
        from random import randint
        
        number_of_checks = 5 # Should be 20
        for i in range(number_of_checks):
            x = randint(2, n-1)
            Witness = self.__miller_rabin(x, n)
    
            # Is x a witness? If so, n is definitely composite.
            if (Witness == True):
                return False
    
        # If we made it here, then none of the random numbers were witnesses
        return True


    def __find_prime(self, lowerBound, upperBound):
        """
        Uses probablyPrime() and a random number generator to produce a prime.
        
        Inputs:
        --- lowerBound
        --- upperBound
        
        Output:
        --- a number p between lowerBound and upperBound which is very likely 
            to be prime.
        """
        
        from random import randint
    
        while True:
            potential_prime = randint(lowerBound, upperBound)
            if self.__probably_prime(potential_prime) == True:
                return potential_prime
    
    
    def __generate_rsa_primes(self, b):
        """
        Generates two b-bit primes.
        """
        
        p = self.__find_prime(2**b, 2**(b+1)-1)
        q = self.__find_prime(2**b, 2**(b+1)-1)
    
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
        
        from random import randint
        
        modulus = (p-1) * (q-1)
    
        while True:
            e = randint(2, modulus - 1)
            if self.__extended_gcd(e, modulus)[0] == 1:
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
    
        return self.__get_mod_inverse(e, (p-1)*(q-1))
    
if __name__ == "__main__":
    rsa = RSA(100)
    print("\nPlease use rsa.set_private_key() and rsa.set_public_key() to set"
        + " a private key before use. You may pass in an optional argument" 
        + " private_key = [N, d] into rsa.set_private_key() and"
        + " public_key = [N, e] into rsa.set_public_key()"
        + " if you have your own keys. If not, keys will be created for you.")
    print("\nOnce you have set your public and private keys,"
        + " run rsa.clear_security_flaws() to delete unnecessary information"
        + " that may be used to break your RSA security.\n")