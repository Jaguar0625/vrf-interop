import os
from pathlib import Path

from cffi import FFI

ffi_builder = FFI()

catapult_client_root = Path(os.environ.get('CATAPULT_CLIENT_ROOT'))
catapult_default_bin_directory = catapult_client_root / '_build' / 'bin'

extra_link_args = []
if 'Darwin' == os.uname().sysname:
	extra_link_args += ['-rpath', str(catapult_default_bin_directory)]
	boost_lib_bin_directory = os.environ.get('BOOST_BIN_DIRECTORY', None)
	if boost_lib_bin_directory:
		extra_link_args += ['-rpath', str(boost_lib_bin_directory)]

ffi_builder.set_source(
	'_vrf',
	r'''
		#include "VrfShim.h"
	''',
	include_dirs = [
		catapult_client_root / 'examples' / 'vrfinterop' / 'cdll',
		catapult_client_root / 'src'
	],
	library_dirs = [str(catapult_default_bin_directory)],
	libraries=['catapult.cvrf'],
	extra_link_args=extra_link_args)

ffi_builder.cdef('''
	struct CVrfProof {
		unsigned char Gamma[32];
		unsigned char VerificationHash[16];
		unsigned char Scalar[32];
	};
''')

ffi_builder.cdef('''
	void CatapultGenerateVrfProof(
			const unsigned char* alpha,
			unsigned int alphaSize,
			const unsigned char* privateKey,
			struct CVrfProof* vrfProof);

	void CatapultVerifyVrfProof(
			const struct CVrfProof* vrfProof,
			const unsigned char* alpha,
			unsigned int alphaSize,
			const unsigned char* publicKey,
			unsigned char* hash512);

	void CatapultGenerateVrfProofHash(const unsigned char* gamma, unsigned char* hash512);
''')

if '__main__' == __name__:
	ffi_builder.compile(verbose=True)
