# This Makefile configures hax extraction and verification for the
# "securedrop_protocol_minimal" crate, as documented here:
# https://github.com/freedomofpress/securedrop-protocol/wiki/Verification#how-are-f-modules-extracted-from-protocol-minimal

# Goal: extract everything except `storage`
HAX_TARGETS := +**
HAX_TARGETS += -securedrop_protocol_minimal::storage::**
HAX_TARGETS += -securedrop_protocol_minimal::traits::**
HAX_TARGETS += -securedrop_protocol_minimal::keys::**
HAX_TARGETS += -securedrop_protocol_minimal::bundle::**
HAX_TARGETS += -securedrop_protocol_minimal::journalist::**
HAX_TARGETS += -securedrop_protocol_minimal::server::**
HAX_TARGETS += -securedrop_protocol_minimal::source::**
HAX_TARGETS += -securedrop_protocol_minimal::setup::**
HAX_TARGETS += -securedrop_protocol_minimal::wire::**
HAX_TARGETS += -securedrop_protocol_minimal::encrypt_decrypt::**
HAX_TARGETS += -securedrop_protocol_minimal::api::**

# Admit modules we extract but that fail panic freedom:
HAX_ADMITS := Securedrop_protocol_minimal.Message.fst
HAX_ADMITS += Securedrop_protocol_minimal.Metadata.fst
HAX_ADMITS += Securedrop_protocol_minimal.Ciphertext.fst
# These both call `RngCore::fill_bytes` which panics
HAX_ADMITS += Securedrop_protocol_minimal.Primitives.fst
HAX_ADMITS += Securedrop_protocol_minimal.Primitives.X25519.fst

REPO_ROOT = $(shell git rev-parse --show-toplevel)
PROOF_DIR = proofs/fstar/extraction

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

# Keep in sync with ".github/workflows/hax.yml":
FSTAR_EXPECTED_VERSION = F* 2026.03.24
FSTAR_ACTUAL_VERSION   = $(shell fstar.exe --version 2>/dev/null | head -1)
.PHONY: compat-fstar
compat-fstar:  # Internal: Check F* version.
	@[ "$(FSTAR_ACTUAL_VERSION)" = "$(FSTAR_EXPECTED_VERSION)" ] || \
	  { echo "Error: expected fstar.exe version '$(FSTAR_EXPECTED_VERSION)', got '$(FSTAR_ACTUAL_VERSION)'"; exit 1; }

.PHONY: extract
extract:  # Internal/CI: Run hax extraction.
	cargo hax into -i '$(HAX_TARGETS)' fstar

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
	@cargo pkgid hax-lib 2>/dev/null | sed 's/.*@//'

.PHONY: help
help: ## Print this message.
	@printf "Subcommands:\n\n"
	@perl -F':.*##\s+' -lanE '$$F[1] and say "\033[36m$$F[0]\033[0m : $$F[1]"' $(MAKEFILE_LIST) \
		| sort \
		| column -s ':' -t
