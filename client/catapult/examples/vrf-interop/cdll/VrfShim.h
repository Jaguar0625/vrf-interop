#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct CVrfProof {
	unsigned char Gamma[32];
	unsigned char VerificationHash[16];
	unsigned char Scalar[32];
};

#ifdef __cplusplus
}
#endif
