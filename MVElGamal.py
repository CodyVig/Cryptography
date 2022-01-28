### Prerequisite functions

# Entended GCD:
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

# ASCII Functions

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


# Elliptic Curve Functions

def isElliptic(E, p):
    [A, B] = E
    D = (4*A**3 + 27*B**2) %p

    if(D == 0):
        return False
    else:
        return True


def onCurve(P, E, p):

    # Check if P is the point at infinity
    if (P == 'O'):
        # 'O' is only on *elliptic* curves
        if isElliptic(E, p):
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


def addPoints(P, Q, E, p):
    """
    Adds two points on an elliptic curve. (If one of the points is O, input as +Infinity)

    Inputs:
    --- E: a list [a, b] of coefficients of elliptic curve y^2 = x^3 + ax + b;
    --- P: a point on E;
    --- Q: a point on E;
    --- p: a prime > 2.

    Output:
    --- The point P + Q on E.
    """


    # Are these points on the curve?
    if (onCurve(P, E, p) == False):
        raise ValueError("First argument " + str(P) +" is not a point on E.")
    if (onCurve(Q, E, p) == False):
        raise ValueError("Second argument " + str(Q) + " is not a point on E.")

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
            L = getModInverse((x2 - x1), p) * (y2 - y1)
        else:
            L = getModInverse(2*y1, p) * (3*x1**2 + a)

    L = L%p
    x3 = L**2 - x1 - x2
    y3 = L * (x1 - x3) - y1

    return [x3%p, y3%p]
  
  
# Misc

def fastPowerSmall(g, A, N):
    """Returns g^A (mod N) using the algorithm in HW 2 Problem 2(b)."""

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


def getBinary(A):
    """Returns the coefficients [A0, A1, ..., Ar] such that A = A0 + A1*2 + ... + A_r*2^r"""

    x = A; i = 0
    binary_rep = []

    # We need divisionWithRemainder from HW 1:
    def divisionWithRemainder(a, b):
        """Long divides a/b to get [q,r] such that a = bq + r"""

        r = a%b
        q = (a - r)/b

        return [q, r]

    while(x != 0):
        [q, r] = divisionWithRemainder(x, 2)
        binary_rep.append(r)
        x = q
        if(x == 0):
            return binary_rep
        i += 1


def getModInverse(a, p):
    """Returns the inverse of a mod p"""

    [g, u, v] = extendedGCD(a, p)

    if (g != 1):
        raise ValueError("The arguments of getModInverse are not coprime!")

    return u % p
  

# Primes

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
    number_of_checks = 20
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

    while True:
        potential_prime = ZZ.random_element(lowerBound, upperBound)
        if probablyPrime(potential_prime) == True:
            return potential_prime
          
          
### ElGamal code

def MVParameterCreation(b):

    # First create a prime of b bits.
    p = findPrime(2**(b), 2**(b+1))

    P = 'O'
    while (P == 'O'):
        # Generate the parameters
        [E, P] = generateEllipticCurveAndPoint(p)

        # Make sure P has order > 2.
        if (addPoints(P, P, E, p) == 'O'):
            P = 'O'
        else:
            return [E, P, p]
          
          
def MVKeyCreation(pubParams):

    [E, P, p] = pubParams

    while True:
        # Choose a secret privateKey (nA in notes):
        privateKey = ZZ.random_element(p)

        # deduce the publicKey:
        publicKey = doubleAndAddSmall(P, privateKey, E, p)

        # Make sure the publicKey is useable!
        if(publicKey == 'O' or publicKey[1] == 0):
            continue
        else:
            return [privateKey, publicKey]
          
          
def MVEncrypt(pubParams, m1, m2, publicKey):
    """
    This follows the encryption algorithm discussed on page 365 of [HPS].
    """

    [E, P, p] = pubParams
    Q = publicKey

    while True:
        # Choose a random k
        k = ZZ.random_element(p)

        # R = kP
        R = doubleAndAddSmall(P, k, E, p)

        # S = kQ
        S = doubleAndAddSmall(Q, k, E, p)

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
              
          
def MVDecrypt(pubParams, cipherText, privateKey):

    [E, P, p]   = pubParams
    [R, c1, c2] = cipherText
    n = privateKey

    # T = nR
    T = doubleAndAddSmall(R, n, E, p)
    [xt, yt] = T

    xt_inverse = getModInverse(xt, p)
    yt_inverse = getModInverse(yt, p)

    m1_prime = (xt_inverse * c1) % p
    m2_prime = (yt_inverse * c2) % p

    return [m1_prime, m2_prime]
