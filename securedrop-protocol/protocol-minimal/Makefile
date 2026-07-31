# This Makefile configures hax extraction and verification for the
# "securedrop_protocol_minimal" crate, as documented here:
# https://github.com/freedomofpress/securedrop-protocol/wiki/Verification#how-are-f-modules-extracted-from-protocol-minimal

include versions.env

HAX_VERSION = $(shell cargo pkgid hax-lib 2>/dev/null | sed 's/.*@//')
HAX_IMAGE = hax:$(HAX_VERSION)

# NB. We don't use the high-level libcrux crate directly.  Since libcrux's
# sub-crates have various version numbers that all point to the same Git ref,
# here we query for libcrux-traits, which we do use, as a proxy.
LIBCRUX_VERSION = $(shell cargo pkgid libcrux-traits 2>/dev/null | sed 's/.*@//')

HAX_TARGETS := +**
HAX_TARGETS += -securedrop_protocol_minimal::storage::**
HAX_TARGETS += -securedrop_protocol_minimal::server::**
# We keep in the `Client` trait which is used by the source and journalist modules
# but keep out the other traits which don't extract
HAX_TARGETS += -securedrop_protocol_minimal::api::**
HAX_TARGETS += +securedrop_protocol_minimal::api::Client

# Admit modules we extract but that fail panic freedom:
HAX_ADMITS := Securedrop_protocol_minimal.Message.fst
HAX_ADMITS += Securedrop_protocol_minimal.Ciphertext.fst

REPO_ROOT = $(shell git rev-parse --show-toplevel)
PROOF_DIR = proofs/fstar/extraction

# Targets below MAY prefix their commands with `$(CONTAINER_RUN)` to run inside
# the $HAX_IMAGE when $CONTAINER is set.  Targets that do so SHOULD be redefined
# here to establish a dependency on `compat-hax`.
ifdef CONTAINER
CONTAINER_RUN = docker run --rm \
	--volume $(REPO_ROOT):/work \
	--workdir /work/$(CURDIR:$(REPO_ROOT)/%=%) \
	--env CARGO_TARGET_DIR=/work/securedrop-protocol/target/container \
	$(HAX_IMAGE)

extract: compat-hax
endif

.DEFAULT_GOAL := help

.PHONY: clean
clean:  ## Clean the Cargo and F* caches, and reset extracted F* modules.
	cargo clean
	rm -rf $(REPO_ROOT)/.fstar-cache
	rm -f $(PROOF_DIR)/.depend
	rm -f $(PROOF_DIR)/hax.fst.config.json
	rm -f $(PROOF_DIR)/*.fst

.PHONY: compat
compat: compat-fstar  ## Check that hax dependencies are at the right versions.

FSTAR_EXPECTED_VERSION = F* $(FSTAR_VER)
FSTAR_ACTUAL_VERSION   = $(shell fstar.exe --version 2>/dev/null | head -1)
.PHONY: compat-fstar
compat-fstar:  # Internal: Check F* version.
	@[ "$(FSTAR_ACTUAL_VERSION)" = "$(FSTAR_EXPECTED_VERSION)" ] || \
	  { echo "Error: expected fstar.exe version '$(FSTAR_EXPECTED_VERSION)', got '$(FSTAR_ACTUAL_VERSION)'"; exit 1; }

.PHONY: compat-hax-image
compat-hax-image:  # Internal: Check that $HAX_IMAGE is present.
	@[ -n "$(HAX_VERSION)" ] || \
	  { echo "Error: could not determine the hax-lib version; is Cargo working?"; exit 1; }
	@docker image inspect $(HAX_IMAGE) >/dev/null 2>&1 || \
	  { echo "Error: missing image '$(HAX_IMAGE)'; build and tag it per <https://github.com/cryspen/hax#installation>."; exit 1; }

.PHONY: compat-hax
compat-hax: compat-hax-image  # Internal: Check that $HAX_IMAGE has the expected $HAX_VERSION.
	@actual=$$(docker run --rm $(HAX_IMAGE) cargo-hax --version 2>/dev/null | sed -n 's/^version=//p'); \
	[ "$$actual" = "$(HAX_VERSION)" ] || \
	  { echo "Error: expected cargo-hax version '$(HAX_VERSION)', got '$$actual'"; exit 1; }

.PHONY: extract
extract:  ## Run hax extraction, without verifying. (Prefix with "CONTAINER=1" to run containerized.)
	$(CONTAINER_RUN) cargo-hax into -i '$(HAX_TARGETS)' fstar

.PHONY: hax
hax: compat extract verify  ## Run hax extraction, then type-check and verify extracted proofs.

.PHONY: verify
verify:  # Internal/CI: Type-check and verify extracted proofs.
	# Type-check (fail fast):
	OTHERFLAGS="--lax" $(MAKE) -C $(PROOF_DIR)
	# Verify:
	$(MAKE) -C $(PROOF_DIR) ADMIT_MODULES="$(HAX_ADMITS)" all-keep-going

.PHONY: hax-lib-version
hax-lib-version:  # Internal: Query Cargo for the hax-lib version.
	@echo $(HAX_VERSION)

.PHONY: hax-lib-version
libcrux-version:  # Internal: Query Cargo for the libcrux version.
	@echo $(LIBCRUX_VERSION)

.PHONY: help
help: ## Print this message.
	@printf "Subcommands:\n\n"
	@perl -F':.*##\s+' -lanE '$$F[1] and say "\033[36m$$F[0]\033[0m : $$F[1]"' $(MAKEFILE_LIST) \
		| sort \
		| column -s ':' -t
