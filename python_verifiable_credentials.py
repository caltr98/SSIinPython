import json
import time
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
from eth_account import Account
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip39MnemonicValidator
from cryptography.hazmat.backends import default_backend


def generate_ethereum_private_key(mnemonic: str):
	"""Generates Ethereum private key and DID from a mnemonic."""
	if not Bip39MnemonicValidator().IsValid(mnemonic):
		raise ValueError("Invalid mnemonic")

	seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
	eth_account = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM).DeriveDefaultPath()
	private_key_bip44 = eth_account.PrivateKey().Raw().ToHex()

	acct = Account.from_key(private_key_bip44)
	public_address_bip44 = acct.address
	did_bip44 = f'did:ethr:{public_address_bip44}'

	return private_key_bip44, public_address_bip44, did_bip44


def generate_secp256k1_key_pair(private_key_bip44: str):
	"""Generates SECP256K1 private key and public key from Ethereum private key."""
	privkey = ec.derive_private_key(int(private_key_bip44, 16), ec.SECP256K1(), default_backend())
	public_key = privkey.public_key()
	return privkey, public_key


def create_vc_payload_for_jwt(DIDOfHolder: str, DIDOfIssuer: str, attributes: dict):
	"""Creates a Verifiable Credential payload."""
	vc_payload = {
		"vc": {
			"@context": [
				"https://www.w3.org/2018/credentials/v1"
			],
			"type": [
				"VerifiableCredential"
			],
			"credentialSubject": attributes
		},
		"sub": DIDOfHolder,
		"nbf": int(time.time()),
		"iss": DIDOfIssuer
	}
	return vc_payload


def sign_vc(vc_payload, privkey):
	"""Signs the VC payload to create a JWT."""
	return jwt.encode(vc_payload, privkey, algorithm="ES256K")


def create_VerifiableCredential_2020(did_of_holder, did_of_issuer, key_for_signature, attributes):
	"""Creates a Verifiable Credential with JWTProof2020."""
	vc_payload = create_vc_payload_for_jwt(did_of_holder, did_of_issuer, attributes)
	my_jwt = sign_vc(vc_payload, key_for_signature)

	# JWTProof2020 structure
	jwt_proof = {
		"type": "JWTProof2020",
		"jwt": my_jwt
	}

	# Verifiable Credential structure
	credential = {
		"credentialSubject": {
			"you": "Rock",
			"id": did_of_holder,
		},
		"issuer": {
			"id": did_of_issuer,
		},
		"type": ["VerifiableCredential"],
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
		"proof": jwt_proof  # JWT proof included here
	}

	return credential


def verify_vc(jwt_proof, public_key):
	"""Verifies the JWTProof2020 contained in a Verifiable Credential."""
	try:
		# Extract the JWT from the proof
		jwt_token = jwt_proof["jwt"]

		# Verify the JWT with the public key
		decoded = jwt.decode(jwt_token, key=public_key, algorithms=["ES256K"])

		# Return the decoded JWT if it's valid
		return decoded
	except jwt.InvalidTokenError as e:
		print(f"JWT Verification Failed: {e}")
		return None


def verify_verifiable_credential_VerifiableCredential_2020(credential, public_key):
	"""Verifies a Verifiable Credential with JWTProof2020."""
	try:
		# Extract the proof from the credential
		jwt_proof = credential["proof"]

		# Verify the JWT within the proof
		decoded = verify_vc(jwt_proof, public_key)

		if decoded:
			print("✅ Verifiable Credential Verified Successfully!")
			print("Decoded JWT:", decoded)
			return True
		else:
			print("❌ Verifiable Credential Verification Failed!")
			return False
	except KeyError as e:
		print(f"❌ Error: Missing key in credential: {e}")
		return False


