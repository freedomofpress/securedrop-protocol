HAX_TARGETS := -**
HAX_TARGETS += +securedrop_protocol_minimal::primitives::dh_akem::typed
HAX_TARGETS += +securedrop_protocol_minimal::primitives::mlkem::typed
HAX_TARGETS += +securedrop_protocol_minimal::primitives::xwing::typed
HAX_TARGETS += +securedrop_protocol_minimal::primitives::x25519::typed
HAX_TARGETS += +securedrop_protocol_minimal::message::**
HAX_TARGETS += +securedrop_protocol_minimal::metadata::**
HAX_TARGETS += +securedrop_protocol_minimal::ciphertext::**

REPO_ROOT = $(shell git rev-parse --show-toplevel)
PROOF_DIR = proofs/fstar/extraction

.PHONY: clean
clean:
	cargo clean
	cargo cache -a
	rm -rf $(REPO_ROOT)/.fstar-cache
	rm -f $(PROOF_DIR)/.depend
	rm -f $(PROOF_DIR)/hax.fst.config.json

.PHONY: compat
compat: compat-fstar

# Keep in sync with ".github/workflows/hax.yml":
FSTAR_EXPECTED_VERSION = F* 2025.12.15
FSTAR_ACTUAL_VERSION   = $(shell fstar.exe --version 2>/dev/null | head -1)
.PHONY: compat-fstar
compat-fstar:
	@[ "$(FSTAR_ACTUAL_VERSION)" = "$(FSTAR_EXPECTED_VERSION)" ] || \
	  { echo "Error: expected fstar.exe version '$(FSTAR_EXPECTED_VERSION)', got '$(FSTAR_ACTUAL_VERSION)'"; exit 1; }

.PHONY: extract
extract:
	cargo hax into -i '$(HAX_TARGETS)' fstar

.PHONY: hax
hax: compat extract verify

.PHONY: verify
verify:
	# Type-check (fail fast):
	OTHERFLAGS="--lax" $(MAKE) -C $(PROOF_DIR)
	# Verify:
	$(MAKE) -C $(PROOF_DIR)

.PHONY: hax-lib-version
hax-lib-version:
	@cargo pkgid hax-lib 2>/dev/null | sed 's/.*@//'
