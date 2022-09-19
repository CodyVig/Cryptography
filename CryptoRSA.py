class RSA:
    # __init__ runs upon instantiation and stores these attributes permanently 
    # for each object.
    def __init__(self, b):
        self.bit_size = b
        self.primes = self.__generateRSAPrimes(b)
        self.encryption_exp = self.__generateRSAEncryptionExp(
            self.primes[0], self.primes[1])
        self.decryption_exp = self.__generateRSADecryptionExp(
            self.primes[0], self.primes[1], self.encryption_exp)
        
        
    def get_bit_size(self):
        return self.bit_size
    
    def get_public_key(self):
        return [self.primes[0] * self.primes[1], self.encryption_exp]
    
    def get_private_key(self):
        return [self.primes[0] * self.primes[1], self.decryption_exp]

    def encrypt(self, message):
        """
        Encrypts a plaintext message using RSA encryption.
        
        Inputs:
        --- message : a string you wish to encrypt
        
        Output:
        --- ciphertext = message ** encryption_exponent mod modulus.
        """
    
        [N, e] = self.get_public_key()
        message = self.__textToInt(message)
    
        return self.__fastPowerSmall(message, e, N)
    
    def decrypt(self, cipher):
        """
        Decrypts a ciphertext message using RSA decryption.
        
        Inputs:
        --- cipher : encrypted ciphertext.
        
        Output:
        --- message = cipher ** decryption_exponent mod modulus.
        """
    
        [N, d] = self.get_private_key()
    
        return self.__intToText(self.__fastPowerSmall(cipher, d, N))
    
    # The following functions are needed to perform number-theoretic 
    # calculations to encrypt and decrypt.
    def __divisionWithRemainder(self, a, b):
        """
        Long divides a/b to get [q, r] such that a = bq + r
        """
        
        r = a%b
        q = (a - r)//b
    
        return [q, r]
    
    def __extendedGCD(self, a, b):
        """ 
        Runs extended Euclidean algorithm on inputs (a, b) to find [g, u, v] 
        such that g = gcd(a, b) and au + bv = g. This follows the algorithm 
        introduced in Problem 1.12 of Hoffstein, et al.
        """
    
        u = 1; g = a; x = 0; y = b
    
        while(y != 0):
            [q, t] = self.__divisionWithRemainder(g, y)
            s = u - q*x
            u = x; g = y; x = s; y = t
    
        v = (g - a*u) // b
        return [g, u, v]
    
    def __getModInverse(self, a, p):
        """
        Returns the inverse of a mod p.
        """
    
        [g, u, v] = self.__extendedGCD(a, p)
    
        if (g != 1):
            raise ValueError("The arguments of getModInverse are not coprime!")
    
        return u % p

    def __fastPowerSmall(self, g, A, N):
        """
        Returns g^A (mod N) using a low-space and low-time complexity algorithm.
        """
    
        # If exponent is negative, replace g with the inverse of g
        if (A < 0):
            g = self.__getModInverse(self, g, N)
            A = -A
    
        a = g; b = 1
    
        while(A > 0):
            if(A%2 == 1):
                b = (b*a) % N
    
            a = a**2 % N ; A = A//2
    
        return b
    
    def __textToInt(self, w):
        """
        Takes in a string and outputs an integer satisfying the above equation.
        """
    
        n = 0
    
        for i in range(len(w)):
            n += ord(w[i]) * 256**i
    
        return n


    def __intToText(self, n):
        """
        Takes in an integer and returns its corresponding string using the 
        ASCII dictionary without storing the base-256 expansion.
        """
    
        text = ""
        x = n; i = 0
    
        while(x != 0):
            [x, r] = self.__divisionWithRemainder(x, 256)
            text = text + chr(r)
            if(x == 0):
                return text
            i += 1
            
    def __millerRabin(self, a, n):
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
    
        x = self.__fastPowerSmall(a, q, n)
    
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
    
    def __probablyPrime(self, n):
        """
        Uses Miller-Rabin Witness test a fixed number of times to 
        probablistically determine whether or not input is prime.
        """
        
        from random import randint
        
        number_of_checks = 5 # Should be 20
        for i in range(number_of_checks):
            x = randint(2, n-1)
            Witness = self.__millerRabin(x, n)
    
            # Is x a witness? If so, n is definitely composite.
            if (Witness == True):
                return False
    
        # If we made it here, then none of the random numbers were witnesses
        return True


    def __findPrime(self, lowerBound, upperBound):
        
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
            if self.__probablyPrime(potential_prime) == True:
                return potential_prime
    
    
    def __generateRSAPrimes(self, b):
        """
        Generates two b-bit primes.
        """
        
        p = self.__findPrime(2**b, 2**(b+1)-1)
        q = self.__findPrime(2**b, 2**(b+1)-1)
    
        return [p, q]


    def __generateRSAEncryptionExp(self, p, q):
        """
        Uses random number generation to produce a number coprime to (p-1)*(q-1).
        
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
            if self.__extendedGCD(e, modulus)[0] == 1:
                return e
            
    def __generateRSADecryptionExp(self, p, q, e):
        """
        Calculates the inverse of e mod (p-1)*(q-1).
    
        Inputs:
        --- p
        --- q
        --- e
    
        Output:
        --- d = the inverse of e modulo (p-1)*(q-1).
        """
    
        return self.__getModInverse(e, (p-1)*(q-1))
    
# Instantiation looks like the following   
RSA = RSA(100)