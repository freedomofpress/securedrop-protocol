.PHONY: docs
docs:  ## Generate browsable documentation and call/caller graphs (requires Doxygen and Graphviz)
	@which doxygen >> /dev/null || { echo "doxygen(1) is not available in your \$$PATH.  Is it installed?"; exit 1; }
	@which dot >> /dev/null || { echo "Graphviz's dot(1) is not available in your \$$PATH.  Is it installed?"; exit 1; }
	@doxygen
	@echo "Now open \"$(PWD)/docs/html/index.html\" in your browser."
