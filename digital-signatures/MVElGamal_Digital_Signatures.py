def generate_elgamal_key(p, g):

    a = randint(1, p)
    A = fast_power(g, a, p)

    signing_key = [a, p, g]
    verification_key = [A, p, g]

    return [signing_key, verification_key]

def elgamal_sign(signing_key, document):

    [a, p, g] = signing_key

    # Choose a random k with gcd(k, p-1) = 1
    while True:
        k = randint(1, p)
        if (extended_gcd(k, p-1)[0] == 1):
            s1 = fast_power(g, k, p)
            s2 = ((document - a*s1) * get_mod_inverse(k, p-1))%(p-1)
            return [s1, s2]

def elgamalverify(verification_key, document, signed_document):

    [A, p, g] = verification_key
    [s1, s2] = signed_document

    verify = (fast_power(A, s1, p) * fast_power(s1, s2, p)) % p

    if (verify == fast_power(g, document, p)):
        return True
    else:
        return False