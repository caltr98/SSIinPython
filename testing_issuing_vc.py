import json
import time
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
from eth_account import Account
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip39MnemonicValidator
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Step 1: Use the mnemonic to generate the Ethereum private key
mnemonic = "pilot lazy spend depth defy episode grunt sphere outside setup rough fall"

# Validate the mnemonic using BIP39
if not Bip39MnemonicValidator().IsValid(mnemonic):
	raise ValueError("Invalid mnemonic")

# Generate the BIP-39 seed
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Derive the Ethereum private key using BIP-44 path
eth_account = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM).DeriveDefaultPath()
private_key_bip44 = eth_account.PrivateKey().Raw().ToHex()  # Private key derived from BIP-44

# Verify the key using Ethereum Account (for signing and verification)
acct = Account.from_key(private_key_bip44)
public_address_bip44 = acct.address
did_bip44 = f'did:ethr:{public_address_bip44}'  # The DID derived from Ethereum address

# Step 2: Generate SECP256K1 key pair using cryptography
KEY_TYPE = ec.SECP256K1()
privkey = ec.derive_private_key(int(private_key_bip44, 16), ec.SECP256K1(), default_backend())
public_key = privkey.public_key()


# Prepare the payload with VC as a string
vc_payload = {
	"iss": did_bip44,  # Issuer DID (you can set this to your actual DID)
	"sub": "did:ethr:0x123456789abcdef",  # Subject DID
	"iat": int(time.time()),  # Issued At timestamp
	"nesting": {
		"@context": "asdfgfdewedfgasdfghgfdsdghgfdserftghfdsdf",
		"credentialSubject": {
			"id": "miao",
			"name": "Alice",
			"degree_type": "BachelorDegree",
			"degree_name": "BSc Computer Science",
		},
		"after": "world"
	}
}


my_jwt = jwt.encode(
	vc_payload,  # The Verifiable Credential Payload
	privkey,  # Private key to sign the JWT
	algorithm="ES256K"  # SECP256K1 (Elliptic Curve Signature Algorithm)
)

print("🔐 Signed Verifiable Credential JWT (ES256K):")
print(my_jwt)

# Step 6: Decode and verify the JWT (for testing)
decoded = jwt.decode(my_jwt, key=public_key, algorithms=["ES256K"])

print("\nDecoded JWT payload:")
print(json.dumps(decoded, indent=2))
