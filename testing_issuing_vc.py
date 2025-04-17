from python_verifiable_credentials import (
	generate_ethereum_private_key,
	generate_secp256k1_key_pair,
	create_VerifiableCredential_2020
)
import json

def main():
	mnemonic = "pilot lazy spend depth defy episode grunt sphere outside setup rough fall"
	private_key_bip44, public_address_bip44, did = generate_ethereum_private_key(mnemonic)
	privkey, public_key = generate_secp256k1_key_pair(private_key_bip44)

	attributes = {
		"you": "Rock"
	}

	vc_with_proof = create_VerifiableCredential_2020(did, did, privkey, attributes)

	print("🔐 Verifiable Credential with JWT Proof 2020:")
	print(json.dumps(vc_with_proof, indent=2))

if __name__ == "__main__":
	main()
