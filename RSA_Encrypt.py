"""
RSA Digital Signature / Encryption Algorithm in Python

I may implement a decryption method later on
It would require the user to have the public key in the generated key pair

Some resources used while crafting this program:
    https://dev.to/xfbs/generating-prime-numbers-with-python-and-rust-4663
    https://www.w3resource.com/python-exercises/generators-yield/python-generators-yield-exercise-3.php
    https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    https://stackoverflow.com/questions/18939833/more-elegant-modulo-conversion-between-24hr-time-and-12hr-time
    https://www.cryptool.org/en/cto/rsa-step-by-step/

"""
import math, random


# I am going to convert each letter to int with ORD(), then use RSA on the numbers.
def convert_to_bin(plaintext):
    """
    Converts a given plaintext character by character into binary block form

    """
    converted_text = []

    for x in plaintext:
        # converts the char into a binary byte (8 binary bits)
        converted_text.append(int(format(ord(x), '08b')))

    return converted_text


def convert_to_int(plaintext):
    converted_text = []

    for x in plaintext:
        converted_text.append(ord(x))

    return converted_text


def prime():
    """
    Used to generate a list of prime numbers,
    which are used in the calculation of the public/private keys
    """
    # 1.1: Generate Prime Numbers
    # Gen prime numbers between 2 and 200
    n = 2
    max_num = 200 # The max number we will iterate to in order to generate primes.
    primes = []
    while n <= max_num:
        for x in range(2, int(math.sqrt(n)) + 1):
            # By checking the sqrt(n), rather than n
            # speeds up calculation of prime numbers.
            if n % x == 0:
                # Not prime
                n+=1
        primes.append(n)
        n+=1

    # Now with our list of primes, we need to choose 2 random ones.
    p1 = [random.choice(primes), random.choice(primes)]
    primes = p1
    return primes


def keys(p,q):
    """
    Used to calculate the variable values used in the private key
    I also calculated a public key, I may try to implement a decryption method later
    if the user inputted the respective public key.
    """
    # 2.1 - We calc the RSA modulus by multiplying our prime numbers together.
    # It is used to calculate the range of ciphertext and plaintext.
    n = p * q

    # 2.2 - We calculate the Euler's Totient ϕ(n)
    # This is a value which is used in deriving the keys.
    eulers = (p - 1) * (q - 1)

    # 2.3 - Select the e value, which is used in the public key calculation
    # e can be freely chosen, but it must be comprime to ϕ.
        # which means no 2 numbers have no common divisor except 1.
    e = 0

    while True:
        # Will loop until we find a value which is coprime to ϕ.
        # I have to use a small amount of numbers as python return as error during the encryption
        # process as the calculation results in too large of a number.
        num = random.randint(0, 100)

        # Coprime is where 2 numbers have no common divisor except for 1.
        if math.gcd(eulers, num) == 1 and num > 1:
            e = num
            break

    # 2.4 - Select the d value, which is used in the private key calculation
    # d is the multiplicative inverse to e.
    # Which means that d * e = 1 if modulo ϕ(n)
    d = pow(e, -1, eulers)

    # 2.5 - Keys
    public_key = [n, d]
    private_key = [n, e]

    return [public_key, private_key]


def encrypt(bin_list, private):
    """
    Encrypts the binary blocks with RSA
    Encrypted output is represented as binary blocks
    """

    encrypted_output = []

    for x in range(len(bin_list)):
        encrypted_output.append((bin_list[x] ** private[1]) % private[0])

    return encrypted_output


def convert_to_text(encrypted_output):
    """
    Converts the encrypted binary code into english

    Note:
        # Issue here however, my encrypted numbers were too large to convert back into
        # chr form. So I have to reduce these numbers so they are usable by Unicode
        # IE) keep them below 52 --> Unicode 65-90 (Uppercase), Unicode 97-122 (Lowercase)

    """

    ciphertext = []

    for x in range(len(encrypted_output)):
        value = encrypted_output[x] % 52

        # Now I map the reduced value to an upper or lowercase Unicode integer
        if value < 26:
            ciphertext.append(value + 65) # Uppercase
        else:
            ciphertext.append(value + 71) # Lowercase

    encrypted_text = ''
    for x in range(len(ciphertext)):
        encrypted_text+=str(chr(ciphertext[x]))

    return encrypted_text


def main():
    """
    Main Function
    """
    message = input("Chosen value to convert to RSA?: ")

    # Step 1: Convert the plaintext message into binary form.

    # Below holds a list of the integer encrypted message.
    bin_list = convert_to_bin(message)

    # Step 2: Determine prime numbers to be used.
    primes = prime()
    p = primes[0]
    q = primes[1]

    # Step 3:  Calculate key values.
    keys_ = keys(p,q)
    public = keys_[0]
    private = keys_[1]

    # Step 4: Encryption
    encrypted = encrypt(bin_list, private)

    # step 5: Convert the encrypted binary blocks back into text form
    ciphertext = convert_to_text(encrypted)
    print(f"The encrypted plaintext is: {ciphertext}")

if __name__ == "__main__":
    main()























