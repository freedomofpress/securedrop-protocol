HAX_TARGETS := -**
HAX_TARGETS += +securedrop_protocol_minimal::primitives::xwing::typed

REPO_ROOT = $(shell git rev-parse --show-toplevel)
PROOF_DIR = proofs/fstar/extraction

FSTAR_EXPECTED_VERSION := F* 2025.12.15
FSTAR_ACTUAL_VERSION   := $(shell fstar.exe --version 2>/dev/null | head -1)
.PHONY: compat-fstar
compat-fstar:
	@[ "$(FSTAR_ACTUAL_VERSION)" = "$(FSTAR_EXPECTED_VERSION)" ] || \
	  { echo "Error: expected fstar.exe version '$(FSTAR_EXPECTED_VERSION)', got '$(FSTAR_ACTUAL_VERSION)'"; exit 1; }

.PHONY: compat
compat: compat-fstar

.PHONY: hax
hax: compat

	rm -f $(PROOF_DIR)/*.fst
	cargo hax into -i '$(HAX_TARGETS)' fstar
	OTHERFLAGS="--lax" $(MAKE) -C $(PROOF_DIR)
	make -C $(PROOF_DIR)

.PHONY: clean
clean:
	cargo clean
	cargo cache -a
	rm -rf $(REPO_ROOT)/.fstar-cache
	rm -f $(PROOF_DIR)/.depend
	rm -f $(PROOF_DIR)/hax.fst.config.json
