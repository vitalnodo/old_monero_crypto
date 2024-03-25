from binascii import unhexlify

from some_ecc import curve25519, ed25519
import tiny_keccak

def boolean(a):
    return True if a == "true" else False

with open("tests.txt") as tests_txt:
    for line in tests_txt:
        splitted = line.strip().split(" ")
        cmd = splitted[0]
        if cmd == "check_scalar":
            scalar = unhexlify(splitted[1])
            expected = boolean(splitted[2])
            try:
                curve25519.Scalar.reject_noncanonical(scalar)
            except ValueError:
                assert expected == False
        # random_scalar
        if cmd == "hash_to_scalar":
            try:
                hash_ = unhexlify(splitted[1])
                hash_ = tiny_keccak.keccak256(hash_)
                scalar = curve25519.Scalar.reduce(hash_)
                assert scalar.hex() == splitted[2]
            except:
                assert splitted[1] == "x"
        # generate_keys
        if cmd == "check_key":
            key = unhexlify(splitted[1])
            bool_ = boolean(splitted[2])
            try:
                curve25519.Point.reject_noncanonical(key)
            except ValueError:
                assert expected == False
        if cmd == "secret_key_to_public_key":
            secret = unhexlify(splitted[1])
            correct_scalar = boolean(splitted[2])
            if not correct_scalar:
                continue
            expected_public = unhexlify(splitted[3])
            try:
                secret = ed25519.Scalar.from_bytes(secret)
            except:
                assert correct_scalar == False
                continue
            expected_public = ed25519.Point.from_bytes(expected_public)
            public = ed25519.BasePoint().mul(secret.to_bytes())
            assert public.to_bytes() == expected_public.to_bytes()
