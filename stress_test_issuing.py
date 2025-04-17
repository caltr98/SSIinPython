import json
import time
import random
import string
import argparse
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
from eth_account import Account
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip39MnemonicValidator
from cryptography.hazmat.backends import default_backend


def random_string(length):
	return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def stress_test_vc_jwt(num_iterations: int, payload_size: int):
	mnemonic = "pilot lazy spend depth defy episode grunt sphere outside setup rough fall"

	if not Bip39MnemonicValidator().IsValid(mnemonic):
		raise ValueError("Invalid mnemonic")

	seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
	eth_account = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM).DeriveDefaultPath()
	private_key_bip44 = eth_account.PrivateKey().Raw().ToHex()

	acct = Account.from_key(private_key_bip44)
	public_address_bip44 = acct.address
	did_bip44 = f'did:ethr:{public_address_bip44}'

	privkey = ec.derive_private_key(int(private_key_bip44, 16), ec.SECP256K1(), default_backend())
	public_key = privkey.public_key()

	print(f"🚀 Starting stress test with {num_iterations} iterations")
	print(f"📦 Payload size per VC: {payload_size} characters\n")

	total_sign_time = 0
	total_verify_time = 0

	for i in range(1, num_iterations + 1):
		dummy_data = random_string(payload_size)

		vc_payload = {
			"iss": did_bip44,
			"sub": f"did:ethr:0x123456789abcdef",
			"iat": int(time.time()),
			"nesting": {
				"@context": "https://www.w3.org/2018/credentials/v1",
				"credentialSubject": {
					"id": f"user{i}",
					"data_blob": dummy_data
				}
			}
		}

		# Sign
		start_sign = time.time()
		jwt_token = jwt.encode(vc_payload, privkey, algorithm="ES256K")
		sign_duration = time.time() - start_sign
		total_sign_time += sign_duration

		# Verify
		start_verify = time.time()
		decoded = jwt.decode(jwt_token, key=public_key, algorithms=["ES256K"])
		verify_duration = time.time() - start_verify
		total_verify_time += verify_duration

		print(f"✅ Iteration {i}: Sign: {sign_duration:.4f}s | Verify: {verify_duration:.4f}s")

	print("\n📊 Stress Test Summary:")
	print(f"Total Sign Time: {total_sign_time:.2f} sec")
	print(f"Total Verify Time: {total_verify_time:.2f} sec")
	print(f"Average Sign Time: {total_sign_time/num_iterations:.4f} sec")
	print(f"Average Verify Time: {total_verify_time/num_iterations:.4f} sec")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Stress Test for VC JWT on Raspberry Pi 4")
	parser.add_argument("--iterations", type=int, default=10, help="Number of JWTs to generate/verify")
	parser.add_argument("--payload_size", type=int, default=1000, help="Size of data_blob in characters")

	args = parser.parse_args()
	stress_test_vc_jwt(num_iterations=args.iterations, payload_size=args.payload_size)
