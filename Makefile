.DEFAULT_GOAL := help
DOCS=$(wildcard *.md) $(wildcard **/*.md)

.PHONY: check-lint-deps
check-lint-deps:
	@which npx >> /dev/null || { echo "npx is not installed"; exit 1; }
	@LINT_PRETTIER_VERSION=$$(command -v jq >> /dev/null && jq -r '.packages["node_modules/prettier"].version' package-lock.json 2> /dev/null || echo ""); \
	\
	if [ -z "$$LINT_PRETTIER_VERSION" ]; then \
		echo "Could not parse package-lock.json for dependency versions (is jq installed?)"; \
		exit 0; \
	fi; \
	\
	PRETTIER_INSTALLED=$$(npx --no-install prettier --version 2> /dev/null || echo ""); \
	if [ "$$PRETTIER_INSTALLED" != "$$LINT_PRETTIER_VERSION" ]; then \
		echo "Run 'npm ci' to install the pinned version of Prettier."; \
		exit 1; \
	fi; \


.PHONY: ci-lint
ci-lint:  ## Lint GitHub Actions workflows.
	@poetry run zizmor .

.PHONY: docs-lint
docs-lint: $(DOCS) ## Lint Markdown-format documentation.
	$(MAKE) check-lint-deps
	@npx prettier --check $^

.PHONY: fix
docs-fix: $(DOCS)  ## Apply automatic fixes to Markdown-format documentation.
	$(MAKE) check-lint-deps
	@npx prettier --write $^

.PHONY: doxygen
doxygen:  ## Generate browsable documentation and call/caller graphs (requires Doxygen and Graphviz).
	@which doxygen >> /dev/null || { echo "doxygen(1) is not available in your \$$PATH.  Is it installed?"; exit 1; }
	@which dot >> /dev/null || { echo "Graphviz's dot(1) is not available in your \$$PATH.  Is it installed?"; exit 1; }
	@doxygen
	@echo "Now open \"$(PWD)/docs/html/index.html\" in your browser."

.PHONY: build-wasm
build-wasm:  ## Compile securedrop-protocol crate for wasm32-unknown-unknown (browser compat, requires rust toolchain).
	@which cargo >> /dev/null || { echo "Please install the Rust toolchain"; exit 1; }
	@rustup target list --installed | grep wasm32-unknown-unknown || { echo "Install wasm32 target using \`rustup target add wasm32-unknown-unknown\`"; exit 1; }
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build --manifest-path securedrop-protocol/Cargo.toml --target wasm32-unknown-unknown

.PHONY: fix
fix: docs-fix  ## Apply automatic fixes.

.PHONY: lint
lint: ci-lint docs-lint  ## Run all linters.

.PHONY: help
help: ## Prints this message and exits.
	@printf "Subcommands:\n\n"
	@perl -F':.*##\s+' -lanE '$$F[1] and say "\033[36m$$F[0]\033[0m : $$F[1]"' $(MAKEFILE_LIST) \
		| sort \
		| column -s ':' -t
