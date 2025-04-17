import json
import time
import random
import string

# Importing functions for Verifiable Credential handling
from python_verifiable_credentials import (
	generate_ethereum_private_key,
	generate_secp256k1_key_pair,
	create_vc_payload_for_jwt,
	sign_vc,
	create_VerifiableCredential_2020,
	verify_vc,
	verify_verifiable_credential_VerifiableCredential_2020
)

def random_string(length):
	"""Generates a random string of specified length."""
	return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def stress_test_vc_jwt(num_iterations: int, payload_size: int):
	"""Stress tests VC JWT creation and verification."""
	mnemonic = "pilot lazy spend depth defy episode grunt sphere outside setup rough fall"
	private_key_bip44, public_address_bip44, did = generate_ethereum_private_key(mnemonic)
	privkey, public_key = generate_secp256k1_key_pair(private_key_bip44)

	print(f"🚀 Starting stress test with {num_iterations} iterations")
	print(f"📦 Payload size per VC: {payload_size} characters\n")

	total_sign_time = 0
	total_verify_time = 0

	for i in range(1, num_iterations + 1):
		dummy_data = random_string(payload_size)
		attributes = {
			"id": f"user{i}",
			"data_blob": dummy_data
		}

		vc_payload = create_vc_payload_for_jwt(did, did, attributes)

		# Sign
		start_sign = time.time()
		jwt_token = sign_vc(vc_payload, privkey)
		sign_duration = time.time() - start_sign
		total_sign_time += sign_duration

		# Create Verifiable Credential with JWTProof2020
		credential = create_VerifiableCredential_2020(did, did, privkey, attributes)

		# Verify the Verifiable Credential
		start_verify = time.time()
		verification_result = verify_verifiable_credential_VerifiableCredential_2020(credential, public_key)
		verify_duration = time.time() - start_verify
		total_verify_time += verify_duration

		if verification_result:
			print(f"✅ Iteration {i}: Sign: {sign_duration:.4f}s | Verify: {verify_duration:.4f}s")
		else:
			print(f"❌ Iteration {i}: Verification Failed!")

	print("\n📊 Stress Test Summary:")
	print(f"Total Sign Time: {total_sign_time:.2f} sec")
	print(f"Total Verify Time: {total_verify_time:.2f} sec")
	print(f"Average Sign Time: {total_sign_time/num_iterations:.4f} sec")
	print(f"Average Verify Time: {total_verify_time/num_iterations:.4f} sec")


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Stress Test for VC JWT")
	parser.add_argument("--iterations", type=int, default=10, help="Number of JWTs to generate/verify")
	parser.add_argument("--payload_size", type=int, default=1000, help="Size of data_blob in characters")

	args = parser.parse_args()
	stress_test_vc_jwt(num_iterations=args.iterations, payload_size=args.payload_size)
