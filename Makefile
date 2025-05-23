.DEFAULT_GOAL := help

.PHONY: ci-lint
ci-lint:  ## Lint GitHub Actions workflows.
	@poetry run zizmor .

.PHONY: docs-lint
docs-lint: $(wildcard *.md) $(wildcard **/*.md)  ## Lint Markdown-format documentation.
	@npx prettier --check $^

.PHONY: doxygen
doxygen:  ## Generate browsable documentation and call/caller graphs (requires Doxygen and Graphviz).
	@which doxygen >> /dev/null || { echo "doxygen(1) is not available in your \$$PATH.  Is it installed?"; exit 1; }
	@which dot >> /dev/null || { echo "Graphviz's dot(1) is not available in your \$$PATH.  Is it installed?"; exit 1; }
	@doxygen
	@echo "Now open \"$(PWD)/docs/html/index.html\" in your browser."

.PHONY: help
help: ## Prints this message and exits.
	@printf "Subcommands:\n\n"
	@perl -F':.*##\s+' -lanE '$$F[1] and say "\033[36m$$F[0]\033[0m : $$F[1]"' $(MAKEFILE_LIST) \
		| sort \
		| column -s ':' -t
