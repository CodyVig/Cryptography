### Prerequisite functions


def divisionWithRemainder(a, b):
    """Long divides a/b to get [q, r] such that a = bq + r"""

    r = a%b
    q = (a - r)//b

    return [q, r]


def extendedGCD(a, b):
    """Runs extended Euclidean algorithm on inputs (a, b) to find [g, u, v] such that g = gcd(a, b) and au + bv = g.
       This follows the algorithm introduced in Problem 1.12 of Hoffstein, et al."""

    u = 1; g = a; x = 0; y = b

    while(y != 0):
        [q, t] = divisionWithRemainder(g, y)
        s = u - q*x
        u = x; g = y; x = s; y = t

    v = (g - a*u) // b
    return [g, u, v]


def getModInverse(a, p):
    """Returns the inverse of a mod p"""

    [g, u, v] = extendedGCD(a, p)

    if (g != 1):
        raise ValueError("The arguments of getModInverse are not coprime!")

    return u % p


def fastPowerSmall(g, A, N):
    """Returns g^A (mod N) using a low-space and low-time complexity algorithm."""

    # If exponent is negative, replace g with the inverse of g
    if (A < 0):
        g = getModInverse(g, N)
        A = -A

    a = g; b = 1

    while(A > 0):
        if(A%2 == 1):
            b = (b*a) % N

        a = a**2 % N ; A = A//2

    return b


def textToInt(w):
    """Takes in a string and outputs an integer satisfying the above equation."""

    n = 0

    for i in range(len(w)):
        n += ord(w[i]) * 256**i

    return n


def intToText(n):
    """Takes in an integer and returns its corresponding string using the ASCII dictionary without storing the base-256 expansion."""

    text = ""
    x = n; i = 0

    while(x != 0):
        [x, r] = divisionWithRemainder(x, 256)
        text = text + chr(r)
        if(x == 0):
            return text
        i += 1


### Important RSA functions


def millerRabin(a, n):
    """If a is a Miller-Rabin witness for n, return true. Else, false."""

    # False == Potentially prime
    # True  == Miller-Rabin Witness ---> Definitely composite

    # Write n-1 = 2^k * q where q is odd.
    k = 0
    q = n-1
    while (q%2 == 0):
        k += 1
        q = q//2

    x = fastPowerSmall(a, q, n)

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


def probablyPrime(n):
    """Uses Miller-Rabin Witness test a fixed number of times to probablistically determine whether or not input is prime."""

    number_of_checks = 5 # Should be 20
    for i in range(number_of_checks):
        x = ZZ.random_element(2, n-1)
        Witness = millerRabin(x, n)

        # Is x a witness? If so, n is definitely composite.
        if (Witness == True):
            return False

    # If we made it here, then none of the random numbers were witnesses
    return True


def findPrime(lowerBound, upperBound):
    """Uses probablyPrime() and a random number generator to produce a prime.

    Inputs:
    --- lowerBound
    --- upperBound

    Output:
    --- a number p between lowerBound and upperBound which is very likely to be prime."""

    #i = 0
    while True:
        #i += 1 # To see how many random numbers it took.
        potential_prime = ZZ.random_element(lowerBound, upperBound)
        if probablyPrime(potential_prime) == True:
            return potential_prime
    
    
def generateRSAPrimes(b):
    """Generates two b-bit primes."""

    p = findPrime(2**b, 2**(b+1)-1)
    q = findPrime(2**b, 2**(b+1)-1)

    return [p, q]


def generateRSAEncryptionExp(p, q):
    """Uses random number generation to produce a number coprime to (p-1)*(q-1).

    Inputs (two primes):
    --- p
    --- q

    Output:
    --- a number e such that gcd(e, (p-1)*(q-1)) = 1."""

    modulus = (p-1) * (q-1)

    while True:
        e = ZZ.random_element(2, modulus - 1)
        if extendedGCD(e, modulus)[0] == 1:
            return e


def RSAEncryption(message, PublicKey):
    """Encrypts a plaintext message using RSA encryption.

    Inputs:
    --- message : a numerical representation of a message.
    --- PublicKey = [modulus, encryption_exponent]

    Output:
    --- ciphertext = message ** encryption_exponent mod modulus."""

    N = PublicKey[0]
    e = PublicKey[1]

    return fastPowerSmall(message, e, N)


def RSADecryption(cipher, PrivateKey):
    """Decrypts a ciphertext message using RSA decryption.

    Inputs:
    --- cipher : encrypted ciphertext.
    --- PrivateKey = [modulus, decryption_exponent]

    Output:
    --- message = cipher ** decryption_exponent mod modulus."""

    N = PrivateKey[0]
    d = PrivateKey[1]

    return fastPowerSmall(cipher, d, N)
