#include "VrfShim.h"
#include "catapult/crypto/Vrf.h"

extern "C" {

PLUGIN_API
void CatapultGenerateVrfProof(
		const unsigned char* alpha,
		unsigned int alphaSize,
		const unsigned char* privateKey,
		struct CVrfProof* vrfProof) {
	using namespace catapult::crypto;

	// 1. wrap KeyPair around private key
	auto cppKeyPair = KeyPair::FromPrivate(PrivateKey::FromBuffer({ privateKey, PrivateKey::Size }));

	// 2. call c++ function
	auto cppVrfProof = GenerateVrfProof({ alpha, alphaSize }, cppKeyPair);

	// 3. copy result
	std::memcpy(vrfProof->Gamma, cppVrfProof.Gamma.data(), cppVrfProof.Gamma.size());
	std::memcpy(vrfProof->VerificationHash, cppVrfProof.VerificationHash.data(), cppVrfProof.VerificationHash.size());
	std::memcpy(vrfProof->Scalar, cppVrfProof.Scalar.data(), cppVrfProof.Scalar.size());
}

}
