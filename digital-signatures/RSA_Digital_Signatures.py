def generate_rsa_key(b):

    p = find_prime(2**b, 2**(b+1))
    q = find_prime(2**b, 2**(b+1))
    while (q == p):
        q = find_prime(2**b, 2**(b+1))

    N = p*q
    modulus = (p-1) * (q-1)

    while True:
        e = randint(2, modulus - 1)
        if extended_gcd(e, modulus)[0] == 1:
            d = get_mod_inverse(e, modulus)
            break

    signing_key = [N, e]
    verification_key = [N, d]

    return [signing_key, verification_key]

def rsa_sign(signing_key, document):

    return fast_power(document, signing_key[1], signing_key[0])

def rsa_verify(verification_key, document, signed_document):

    if document == fast_power(signed_document, verification_key[1], verification_key[0]):
        return True
    else:
        return False