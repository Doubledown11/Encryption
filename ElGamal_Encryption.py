import math, random


def prime_EG():
    """
    Step 1 of the key generation process is to select a large prime number
    I wanted to select primes in the 2048 bit size.
    But generating primes in the range 2**2047 to 2**2048 is too resource intensive.
        Tried 512 bits --> Too intensive
        Tried 128 bits --> Too intensive lol

    Decided to use a a small prime number range as in the RSA implementation.

    """
    primes = []
    for x in range(2, 500):
        prime = True
        for y in range(2, x + 1):
            if x % y == 0:
                prime = True
                break
        if prime:
            primes.append(x)
    return random.choice(primes)


def primitive_element(p):
    """
    Step 2 of the key generation process is to select a primitive element a of the
    multiplicative group z^* p
    This set is composed of integers {1,2,...,p-1}

    Must verify g^k mod p != 1 for all integers in the set K*p.

    """
    # Get values in set
    set = []
    for i in range(1, p):
        set.append(i)

    # Check all numbers in range 1:p-1
    primitive_elements = []
    for x in range(1, p):
        # get g value (represented as x)

        # Since g^k mod p needs to produce all elements of Z*p
        # exactly once as k runs from 1 to p-1 we can
        # add results to dict
        dict = {}
        for j in set:
            dict[j] = 0

        for y in range(1, p):  # CAREFUL WE ITERATE UP TO P, BUT NOT ONTO P.
            # Get k values (represented as y)
            # Need to verify that the integer g^k mod p != 1 for all k < p-1
            # so we compute here save in dict
            check = pow(x, y, p)
            if check not in dict.keys():
                continue

            elif dict[check] == 1:
                continue

            else:
                dict[check] += 1

                # After we ensure the check val is in the set, and has no been visited before
            # and we do this for every val generated by g,
            # We consider it a primitive element.
            primitive_elements.append(x)

    # With all primitive elements in the set{1..p-1} generated,
    # I randomly select one
    return random.choice(primitive_elements)


def random_integer(p):
    """
    Step 3 requires us to choose a random integer from the set {2,3,...p-2}
    """

    # Compute the set
    set = []
    for i in range(2, p - 1):
        set.append(i)

    # Choose a random integer from the set
    return random.choice(set)


def b_calc_eg(a, d, p):
    """
    Step 4: Compute the Beta value.
    """
    return pow(a, d, p)


def gcd(p):
    """
    Step 5: Choose an ephemeral key (k) from the set {0,1,2,3..p-2}
    such that gcd(k,p-1) = 1
    Used math for easy gcd calculation
    """

    possible_keys = []
    for x in range(0, p - 1):
        if math.gcd(x, p - 1) == 1:
            possible_keys.append(x)

    return random.choice(possible_keys)


def convert_to_integers(plaintext):
    """
    Step 6:
    Convert the plaintext into integers/binary numbers letter by letter in
    each word.
    Store the numbers in each word in nested lists.
    """

    # Split the plaintext into a list.
    p_list = plaintext.split()

    new_list = []
    # Convert each letter in each word to a integer representation and
    # add to new_list
    for x in range(len(p_list)):
        word = []
        for letter in p_list[x]:
            # Check if the letter is uppercase -- If so add a $ at end
            # Can check for $ later to ID if upper case when mapping
            # encrypted val to uppercase unicode range.
            if letter.isupper() == True:
                converted = str(ord(letter)) + '$'
                word.append(converted)
            else:
                converted = str(ord(letter))
                word.append(converted)

        new_list.append(word)

    return new_list


def s_param(k, p, plaintext_integers):
    """
    Step 7:
    Compute the signature parameters r and s, as r was calc in prior func
    we calc s.
    """

    encrypted_phrase = []
    for x in range(len(plaintext_integers)):
        encrypted_word = []
        for y in range(len(plaintext_integers[x])):
            # We have to check if a letter is upper case by checking the final val
            # in each integer
            if str(plaintext_integers[x][y])[-1] == '$':
                encrypted_letter = int(plaintext_integers[x][y][:-1]) * k % p
                encrypted_word.append(str(encrypted_letter) + '$')  # Add $ back to ID uppercase

            else:
                encrypted_letter = int(plaintext_integers[x][y]) * k % p
                encrypted_word.append(str(encrypted_letter))
        encrypted_phrase.append(encrypted_word)
    return encrypted_phrase


def convert_to_text_EG(int_list):
    """
    Step 8:
    Converts the list of integers back into text.
    Currently only handles lowercase values.
    """

    phrase = ''
    for x in range(len(int_list)):
        word = ''
        for y in range(len(int_list[x])):
            # Check if letter is upper case by looking for $ at end.
            if '$' in int_list[x][y]:
                # Uppercase is unicode 65 to 90 inclusive
                upper_range = 26  # 90-65 since inclusive we add 1.
                word += str(chr((int(int_list[x][y][:-1]) % upper_range) + 65))


            else:
                # Lowercase letters
                lower_range = 26  # AKA 26 letters in the alphabet.
                word += str(chr((int(int_list[x][y]) % lower_range) + 97))

        phrase += word
        phrase += ' '
    return phrase


def main():
    """
    Both parties must perform a diffie-hellman key exchange to derive a shared key k.
    My program does not use this, rather we generate all needed material
    and share the public key with anyone who wishes to use it.

    """

    plaintext = input('Enter plaintext here: ')

    # Step 1: Choose a large prime number
    # NOTE: My primes calculated are not big enough
    prime = prime_EG()

    # Step 2: Choose a primitive element a of the multiplicative group Z*p or a subgroup of Z*p
    # It appears to be a random number between 2 and the prime in step 1
    #           https://www.geeksforgeeks.org/elgamal-encryption-algorithm/
    a = primitive_element(prime)

    # Step 3: Choose a random integer d ∈ (from the set) {2,3,...p-2}
    d = random_integer(prime)

    # Step 4: Compute B (Beta) = a^d mod p
    b = b_calc_eg(a, d, prime)

    # Public key is formed by (p,a,B) -- Used for Encryption in the
    # elgamal digital signature scheme TODO REMOVE FROM PROGRAM.
    # ###### WARNING ##############!!!!!!!!!!!!!!!!!!!!!!###############ERROR
    public_key = (prime, a, b)

    # Private key is d -- Used for decryption (Shared alongside the signed text)
    # Signed text is encrypted then hashed?
    private_key = d

    # Choose a random ephemeral key (K) which is an element in the set {0,1,2,...p-2}
    # Such that gcd(k,p-1) = 1
    # gcd is the greatest common divisor.
    k = gcd(prime)

    # Convert the plaintext into binary/integer values used in
    # encryption process with pub key.
    # Is a matrix with integer values for each letter in each word
    # each nested list is a word in plaintext.
    plaintext_integers = convert_to_integers(plaintext)

    # Encrypt the integers/binary list
    encrypted_ints = s_param(k, prime, plaintext_integers)

    # Convert the encrypted integers back into text
    encrypted_text = convert_to_text_EG(encrypted_ints)
    print(encrypted_text, 'enc text')


if __name__ == "__main__":
    main()
