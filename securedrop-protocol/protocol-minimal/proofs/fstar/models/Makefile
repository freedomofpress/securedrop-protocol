# This Makefile configures hax extraction for dependencies of the
# "securedrop_protocol_minimal" crate, as documented here:
# https://github.com/freedomofpress/securedrop-protocol/wiki/Verification#how-are-f-interfaces-extracted-from-our-dependencies

HAX_LIB_VERSION=$(shell make -C ../../.. -s hax-lib-version)

# include pattern modifiers (e.g. `+`, `+!`, `+:`) are documented
# in `cargo hax into --help`

LIBCRUX_VERSION=41e1b3d57f8f6c2e49f3fb1e6c33dbb92279023d  # FIXME: cfm/libcrux@41e1b3d

# Extraction targets: default exclude
LIBCRUX_ECDH_TARGETS := -**
LIBCRUX_ML_KEM_TARGETS := -**
LIBCRUX_TRAITS_TARGETS := -**
LIBCRUX_CURVE25519_TARGETS := -**
LIBCRUX_CHACHA20POLY1305_TARGETS := -**
LIBCRUX_KEM_TARGETS := -**

# Extraction targets: Autogenerate from rust tree.
# Autogenerate targets with `make update-targets`
include targets.mk

## Manual extraction targets start here ##

# `+!` (no transitive deps): plain `+` pulls in items that cross the
# `Libcrux_kem.Xwing` submodule boundary
# (Try `+:` to avoid dependencies)
LIBCRUX_KEM_TARGETS += +!libcrux_kem::key_gen
LIBCRUX_KEM_TARGETS += +!libcrux_kem::key_gen_derand

# Targets not found using the rust hir-tree, so they are candidates
# for removal
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::Error
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::*::PrivateKey
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::*::PublicKey
LIBCRUX_ECDH_TARGETS += +libcrux_ecdh::*::SharedSecret

LIBCRUX_KEM_TARGETS += +libcrux_kem::Algorithm
LIBCRUX_KEM_TARGETS += +libcrux_kem::Ct
LIBCRUX_KEM_TARGETS += +libcrux_kem::Error
LIBCRUX_KEM_TARGETS += +libcrux_kem::Ss

LIBCRUX_ML_KEM_TARGETS += +libcrux_ml_kem::types::MlKemCiphertext
LIBCRUX_ML_KEM_TARGETS += +libcrux_ml_kem::types::MlKemPrivateKey
LIBCRUX_ML_KEM_TARGETS += +libcrux_ml_kem::types::MlKemPublicKey

LIBCRUX_TRAITS_TARGETS += +libcrux_traits::kem::arrayref::DecapsError
LIBCRUX_TRAITS_TARGETS += +libcrux_traits::kem::arrayref::EncapsError
LIBCRUX_TRAITS_TARGETS += +libcrux_traits::kem::arrayref::KeyGenError

## End manual extractions ##

.PHONY: rust-toolchain
rust-toolchain:
	@rustup toolchain list | grep -q '^nightly' || \
	( \
		echo "error: Rust nightly toolchain is required."; \
		echo "install it with:"; \
		echo "  rustup toolchain install nightly"; \
		exit 1; \
	)


.PHONY: update-targets
update-targets: rust-toolchain
	./auto_targets.sh libcrux


.PHONY: check-targets
check-targets:
	./auto_targets.sh libcrux
	git diff --exit-code -- targets.mk || echo ""; \
		echo "WARNING: targets.mk has changed!"; \
		echo ""; \
		echo "You may need to rerun 'make libcrux'."; \
		exit 1;


.PHONY: libcrux \
	libcrux-clone \
	libcrux-module \
	libcrux-ecdh \
	libcrux-kem \
	libcrux-ml-kem \
	libcrux-traits \
	libcrux-curve25519 \
	libcrux-chacha20poly1305 \
	libcrux-copy-fsti \
	libcrux-append-stubs

libcrux:
	@$(MAKE) libcrux-clone
	@FAILURES=""; \
	\
	for target in \
		libcrux-ecdh \
		libcrux-kem \
		libcrux-ml-kem \
		libcrux-traits \
		libcrux-curve25519 \
		libcrux-chacha20poly1305 \
	; do \
		if ! $(MAKE) $$target; then \
			FAILURES="$$FAILURES $$target"; \
		fi; \
	done; \
	\
	$(MAKE) libcrux-copy-fsti || exit $$?; \
	$(MAKE) libcrux-append-stubs || exit $$?; \
	if [ -n "$$FAILURES" ]; then \
		echo ""; \
		echo "Failed targets:"; \
		for f in $$FAILURES; do \
			echo "  - $$f"; \
		done; \
		echo ""; \
		echo "::Warning:: .fsti files are available in proofs/fstar/models, but may contain extraction errors."; \
		exit 1; \
	fi
	echo "Extraction completed successfully and .fsti files are available in proofs/fstar/models"; \

libcrux-clone:
	@echo "Clone libcrux@$(LIBCRUX_VERSION)"
	@rm -rf libcrux
	@git clone --quiet https://github.com/cfm/libcrux  # FIXME: cfm/libcrux@41e1b3d
	@cd libcrux && git checkout $(LIBCRUX_VERSION) --quiet

libcrux-module:
	@echo "extract $(MODULE) ..."

	@cd $(MODULE) && \
		cargo add --target 'cfg(hax)' hax-lib@$(HAX_LIB_VERSION)

	@set -e; \
	EXTRACT_STATUS=0; \
	\
	cd $(MODULE) && \
		cargo hax into -i "$(TARGETS)" fstar --interfaces '+!**' \
		|| EXTRACT_STATUS=$$?; \
	\
	if [ $$EXTRACT_STATUS -ne 0 ]; then \
		echo ""; \
		echo "ERROR: hax extraction failed for module $(MODULE)"; \
		echo ""; \
		echo "This likely means one or more problem targets:"; \
		printf '  %s\n' "$(TARGETS)"; \
		exit $$EXTRACT_STATUS; \
	fi


libcrux-copy-fsti:
	@cp libcrux/*/proofs/fstar/extraction/*.fsti . 2>/dev/null || true
	@cp libcrux/crates/algorithms/*/proofs/fstar/extraction/*.fsti . 2>/dev/null || true

libcrux-ecdh:
	$(MAKE) libcrux-module \
		MODULE=libcrux/libcrux-ecdh \
		TARGETS="$(LIBCRUX_ECDH_TARGETS)"


libcrux-kem:
	$(MAKE) libcrux-module \
		MODULE=libcrux/libcrux-kem \
		TARGETS="$(LIBCRUX_KEM_TARGETS)"


libcrux-ml-kem:
	$(MAKE) libcrux-module \
		MODULE=libcrux/libcrux-ml-kem \
		TARGETS="$(LIBCRUX_ML_KEM_TARGETS)"


libcrux-traits:
	$(MAKE) libcrux-module \
		MODULE=libcrux/traits \
		TARGETS="$(LIBCRUX_TRAITS_TARGETS)"


libcrux-curve25519:
	$(MAKE) libcrux-module \
		MODULE=libcrux/crates/algorithms/curve25519 \
		TARGETS="$(LIBCRUX_CURVE25519_TARGETS)"


libcrux-chacha20poly1305:
	$(MAKE) libcrux-module \
		MODULE=libcrux/crates/algorithms/chacha20poly1305 \
		TARGETS="$(LIBCRUX_CHACHA20POLY1305_TARGETS)"

libcrux-append-stubs:
	@find . -name '*.fsti.stub' | while read -r stub; do \
		dst=$${stub%.stub}; \
		m='/// STUB (AUTO INSERT BY MAKEFILE)'; \
		tmp=$$(mktemp); \
		\
		if [ -f "$$dst" ]; then \
			awk -v m="$$m" '$$0==m {exit} {print}' "$$dst" > "$$tmp"; \
		else \
			: > "$$tmp"; \
		fi; \
		\
		printf '%s\n' "$$m" >> "$$tmp"; \
		cat "$$stub" >> "$$tmp"; \
		mv "$$tmp" "$$dst"; \
	done
