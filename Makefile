.PHONY: all lint check test

SCRIPT_DIRS := lib scripts modules

# Find all .sh files across script dirs
SH_FILES := $(shell find $(SCRIPT_DIRS) -name "*.sh" 2>/dev/null)

all: lint check test

lint: ## bash -n syntax check on all .sh files
	@fail=0; \
	for f in $(SH_FILES); do \
		echo "Linting: $$f"; \
		bash -n "$$f" || { echo "FAIL: $$f"; fail=1; }; \
	done; \
	[ $$fail -eq 0 ] && echo "Lint passed." || { echo "Lint failed."; exit 1; }

check: ## shellcheck on all .sh files (errors fail, warnings OK)
	@which shellcheck > /dev/null 2>&1 || { echo "shellcheck not installed. Run: apt install shellcheck"; exit 1; }
	@fail=0; \
	for f in $(SH_FILES); do \
		echo "ShellCheck: $$f"; \
		shellcheck --severity=error -e SC1091 "$$f" || fail=1; \
	done; \
	[ $$fail -eq 0 ] && echo "ShellCheck passed." || { echo "ShellCheck failed."; exit 1; }

test: ## run bats tests from tests/ (skips if no .bats files found)
	@which bats > /dev/null 2>&1 || { echo "bats not installed. Run: apt install bats"; exit 1; }
	@if ls tests/*.bats > /dev/null 2>&1; then \
		echo "Running bats tests..."; \
		bats tests/*.bats; \
	else \
		echo "No .bats test files found in tests/ — skipping."; \
	fi

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-10s %s\n", $$1, $$2}'
