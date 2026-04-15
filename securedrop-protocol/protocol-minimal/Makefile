HAX_TARGETS := -**
HAX_TARGETS += +securedrop_protocol_minimal::primitives::dh_akem::typed
HAX_TARGETS += +securedrop_protocol_minimal::primitives::mlkem::typed
HAX_TARGETS += +securedrop_protocol_minimal::primitives::xwing::typed
HAX_TARGETS += +securedrop_protocol_minimal::primitives::x25519::typed
HAX_TARGETS += +securedrop_protocol_minimal::message::**
HAX_TARGETS += +securedrop_protocol_minimal::metadata::**

REPO_ROOT = $(shell git rev-parse --show-toplevel)
PROOF_DIR = proofs/fstar/extraction

.DEFAULT_GOAL := help

.PHONY: clean
clean:  ## Clean the Cargo and F* caches.
	cargo clean
	cargo cache -a
	rm -rf $(REPO_ROOT)/.fstar-cache
	rm -f $(PROOF_DIR)/.depend
	rm -f $(PROOF_DIR)/hax.fst.config.json

.PHONY: compat
compat: compat-fstar  ## Check that hax dependencies are at the right versions.

# Keep in sync with ".github/workflows/hax.yml":
FSTAR_EXPECTED_VERSION = F* 2025.12.15
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
	$(MAKE) -C $(PROOF_DIR)

.PHONY: hax-lib-version
hax-lib-version:  # Internal: Query Cargo for the hax-lib version.
	@cargo pkgid hax-lib 2>/dev/null | sed 's/.*@//'

.PHONY: help
help: ## Print this message.
	@printf "Subcommands:\n\n"
	@perl -F':.*##\s+' -lanE '$$F[1] and say "\033[36m$$F[0]\033[0m : $$F[1]"' $(MAKEFILE_LIST) \
		| sort \
		| column -s ':' -t