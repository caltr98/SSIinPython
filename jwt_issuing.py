import jwt
from cryptography.hazmat.primitives.asymmetric import ec

KEY_TYPE = ec.SECP256K1()
privkey = ec.generate_private_key(KEY_TYPE)

print(privkey)
my_jwt = jwt.encode(
	{ "hello": "world", "hello2":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hello4":{"hello5":"haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} },
	privkey,
	algorithm="ES256K", # nistp256 aka ec.SECP256R1()
)

print(my_jwt)

decoded = jwt.decode(my_jwt, key=privkey.public_key(), algorithms=["ES256K"])

print(decoded)

