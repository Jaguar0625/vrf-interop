#pragma once
#include "catapult/plugins.h"

#ifdef __cplusplus
extern "C" {
#endif

struct CVrfProof {
	unsigned char Gamma[32];
	unsigned char VerificationHash[16];
	unsigned char Scalar[32];
};

PLUGIN_API
void CatapultGenerateVrfProof(
		const unsigned char* alpha,
		unsigned int alphaSize,
		const unsigned char* privateKey,
		struct CVrfProof* vrfProof);

PLUGIN_API
void CatapultVerifyVrfProof(
		const struct CVrfProof* vrfProof,
		const unsigned char* alpha,
		unsigned int alphaSize,
		const unsigned char* publicKey,
		unsigned char* hash512);

PLUGIN_API
void CatapultGenerateVrfProofHash(const unsigned char* gamma, unsigned char* hash512);

#ifdef __cplusplus
}
#endif
