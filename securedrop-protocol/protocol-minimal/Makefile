HAX_TARGETS := -**
HAX_TARGETS += +securedrop_protocol_minimal::primitives::xwing::typed

REPO_ROOT = $(shell git rev-parse --show-toplevel)
PROOF_DIR = proofs/fstar/extraction

.PHONY: hax
hax:
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
