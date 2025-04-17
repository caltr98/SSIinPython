from authlib.jose import jwt, JsonWebKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# 1. Generate a private EC key on secp256k1
private_key = ec.generate_private_key(ec.SECP256K1())

# 2. Convert private key to JWK
private_jwk = JsonWebKey.import_key(private_key, {"kty": "EC"})

# 3. Verifiable Credential-style payload
vc_payload = {
	"sub": "did:ethr:0x123456789abcdef",  # Subject DID
	"nesting": {
		"@context": "asdfgfdewedfgasdfghgfdsdghgfdserftghfdsdf",
		"credentialSubject": {
			"cuai": "cia",
			"id": "miao",
			"name": "Alice",
			"degree_type": "BachelorDegree",
			"degree_name": "BSc Computer Science",
			"issuanceDate": "2021-01-01T12:00:00Z",
		},
		"after": "world"
	}
}

# 4. JWT header
header = {"alg": "ES256K", "typ": "JWT"}

# 5. Sign the JWT
signed_jwt = jwt.encode(header, vc_payload, private_jwk)

# 6. Print the JWT
print("Serialized JWT:")
print(signed_jwt)

# 7. Export public key (to share with verifier)
public_key = private_key.public_key()
public_jwk = JsonWebKey.import_key(public_key, {"kty": "EC"})
