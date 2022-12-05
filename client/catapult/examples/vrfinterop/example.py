from _vrf import lib, ffi
from binascii import hexlify, unhexlify
from collections import namedtuple
from symbolchain.symbol.KeyPair import KeyPair
from symbolchain.CryptoTypes import PrivateKey

TestCaseInput = namedtuple('TestCaseInput', ['private_key', 'alpha'])
TestCaseOutput = namedtuple('TestCaseInput', ['gamma', 'verification_hash', 'scalar', 'beta'])
TestCase = namedtuple('TestCase', ['input', 'output'])

test_cases = [
	TestCase(
		TestCaseInput('9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60', ''),
		TestCaseOutput(
			'9275DF67A68C8745C0FF97B48201EE6DB447F7C93B23AE24CDC2400F52FDB08A',
			'1A6AC7EC71BF9C9C76E96EE4675EBFF6',
			'0625AF28718501047BFD87B810C2D2139B73C23BD69DE66360953A642C2A330A',
			'A64C292EC45F6B252828AFF9A02A0FE88D2FCC7F5FC61BB328F03F4C6C0657A9D26EFB23B87647FF54F71CD51A6FA4C4E31661D8F72B41FF00AC4D2EEC2EA7B3'
		)
	),
	TestCase(
		TestCaseInput('4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB', '72'),
		TestCaseOutput(
			'84A63E74ECA8FDD64E9972DCDA1C6F33D03CE3CD4D333FD6CC789DB12B5A7B9D',
			'03F1CB6B2BF7CD81A2A20BACF6E1C04E',
			'59F2FA16D9119C73A45A97194B504FB9A5C8CF37F6DA85E03368D6882E511008',
			'CDDAA399BB9C56D3BE15792E43A6742FB72B1D248A7F24FD5CC585B232C26C934711393B4D97284B2BCCA588775B72DC0B0F4B5A195BC41F8D2B80B6981C784E'
		)
	),
	TestCase(
		TestCaseInput('C5AA8DF43F9F837BEDB7442F31DCB7B166D38535076F094B85CE3A2E0B4458F7', 'af82'),
		TestCaseOutput(
			'ACA8ADE9B7F03E2B149637629F95654C94FC9053C225EC21E5838F193AF2B727',
			'B84AD849B0039AD38B41513FE5A66CDD',
			'2367737A84B488D62486BD2FB110B4801A46BFCA770AF98E059158AC563B690F',
			'D938B2012F2551B0E13A49568612EFFCBDCA2AED5D1D3A13F47E180E01218916E049837BD246F66D5058E56D3413DBBBAD964F5E9F160A81C9A1355DCD99B453'
		)
	),
]

def to_hex_string(buffer):
	return hexlify(bytes(buffer)).upper().decode('utf8')

for test_case in test_cases:
	### CatapultGenerateVrfProof ###
	alpha = unhexlify(test_case.input.alpha)
	private_key = PrivateKey(test_case.input.private_key)
	vrf_proof = ffi.new('struct CVrfProof *');
	lib.CatapultGenerateVrfProof(alpha, len(alpha), private_key.bytes, vrf_proof)

	print(f'            gamma: {to_hex_string(vrf_proof.Gamma)}')
	print(f'verification_hash: {to_hex_string(vrf_proof.VerificationHash)}')
	print(f'           scalar: {to_hex_string(vrf_proof.Scalar)}')

	assert test_case.output.gamma == to_hex_string(vrf_proof.Gamma)
	assert test_case.output.verification_hash == to_hex_string(vrf_proof.VerificationHash)
	assert test_case.output.scalar == to_hex_string(vrf_proof.Scalar)

	### CatapultVerifyVrfProof ###
	public_key = KeyPair(private_key).public_key
	proof_hash = bytes(64)
	lib.CatapultVerifyVrfProof(vrf_proof, alpha, len(alpha), public_key.bytes, proof_hash);

	print(f'       proof_hash: {to_hex_string(proof_hash)}')

	assert test_case.output.beta == to_hex_string(proof_hash)

	### CatapultGenerateVrfProofHash ###
	proof_hash_2 = bytes(64)
	lib.CatapultGenerateVrfProofHash(vrf_proof.Gamma, proof_hash_2)

	print(f'     proof_hash_2: {to_hex_string(proof_hash_2)}')

	assert test_case.output.beta == to_hex_string(proof_hash_2)

