HAX_LIB_VERSION=$(shell make -C ../../.. -s hax-lib-version)

LIBCRUX_VERSION=41e1b3d57f8f6c2e49f3fb1e6c33dbb92279023d  # FIXME: cfm/libcrux@41e1b3d
LIBCRUX_ECDH_TARGETS := -**
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::Error
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::*::PrivateKey
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::*::PublicKey
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::*::SharedSecret
LIBCRUX_KEM_TARGETS := -**
LIBCRUX_KEM_TARGETS += +libcrux_kem::Algorithm
LIBCRUX_KEM_TARGETS += +libcrux_kem::Error
LIBCRUX_KEM_TARGETS += +libcrux_kem::PrivateKey
LIBCRUX_KEM_TARGETS += +libcrux_kem::PublicKey
LIBCRUX_KEM_TARGETS += +libcrux_kem::Ct
LIBCRUX_KEM_TARGETS += +libcrux_kem::Ss
LIBCRUX_KEM_TARGETS += +!libcrux_kem::key_gen
LIBCRUX_KEM_TARGETS += +!libcrux_kem::key_gen_derand
LIBCRUX_ML_KEM_TARGETS := -**
LIBCRUX_ML_KEM_TARGETS += +libcrux_ml_kem::types::MlKemPrivateKey
LIBCRUX_ML_KEM_TARGETS += +libcrux_ml_kem::types::MlKemPublicKey
LIBCRUX_ML_KEM_TARGETS += +libcrux_ml_kem::types::MlKemCiphertext
.PHONY: libcrux
libcrux:
	rm -rf $@
	git clone https://github.com/cfm/libcrux  # FIXME: cfm/libcrux@41e1b3d
	cd $@ && git checkout $(LIBCRUX_VERSION)

	cd $@/libcrux-ecdh && cargo add --target 'cfg(hax)' hax-lib@$(HAX_LIB_VERSION)
	cd $@/libcrux-ecdh && cargo hax into -i '$(LIBCRUX_ECDH_TARGETS)' fstar --interfaces '+!**'

	cd $@/libcrux-kem && cargo add --target 'cfg(hax)' hax-lib@$(HAX_LIB_VERSION)
	cd $@/libcrux-kem && cargo hax into -i '$(LIBCRUX_KEM_TARGETS)' fstar --interfaces '+!**'

	cd $@/libcrux-ml-kem && cargo add --target 'cfg(hax)' hax-lib@$(HAX_LIB_VERSION)
	cd $@/libcrux-ml-kem && cargo hax into -i '$(LIBCRUX_ML_KEM_TARGETS)' fstar --interfaces '+!**'

	cp $@/*/proofs/fstar/extraction/*.fsti .