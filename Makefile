CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -ldl

# Build directory
BUILD_DIR = build
BUILD_TESTS_DIR = $(BUILD_DIR)/tests

# Source files
MALLOC_SRC = malloc.c

# Smoke test targets
SMOKE_TESTS = test self_check testing small
SMOKE_BINS = $(addprefix $(BUILD_DIR)/,$(SMOKE_TESTS))

# Scored test targets (tests/test1 through tests/test20)
SCORED_TESTS = 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
SCORED_BINS = $(foreach n,$(SCORED_TESTS),$(BUILD_TESTS_DIR)/test$(n))

# All targets
ALL_BINS = $(SMOKE_BINS) $(SCORED_BINS)

.PHONY: all smoke tests score run check clean help self_check

# Default target
all: smoke tests

# Build smoke tests
smoke: $(SMOKE_BINS)

# Build scored tests
tests: $(SCORED_BINS)

# Create build directories
$(BUILD_DIR) $(BUILD_TESTS_DIR):
	mkdir -p $@

# Run smoke tests
run: smoke
	@echo "Running test..."
	@$(BUILD_DIR)/test
	@echo "\nRunning self_check..."
	@$(BUILD_DIR)/self_check
	@echo "\nRunning testing..."
	@$(BUILD_DIR)/testing
	@echo "\nRunning small..."
	@$(BUILD_DIR)/small

# Run self_check
check: self_check
	@$(BUILD_DIR)/self_check

# Run all scored tests and count passes
score: tests
	@echo "Running scored tests..."
	@passed=0; \
	total=0; \
	for test in $(BUILD_TESTS_DIR)/test*; do \
		if [ -x "$$test" ]; then \
			total=$$((total+1)); \
			if "$$test" > /dev/null 2>&1; then \
				passed=$$((passed+1)); \
			fi; \
		fi; \
	done; \
	echo "Score: $$passed/$$total"

# Build smoke test binaries
$(BUILD_DIR)/test: test.c $(MALLOC_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) test.c $(MALLOC_SRC) -o $@ $(LDFLAGS)

$(BUILD_DIR)/self_check: self_check.c $(MALLOC_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) self_check.c $(MALLOC_SRC) -o $@ $(LDFLAGS)

$(BUILD_DIR)/testing: testing.c $(MALLOC_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) testing.c $(MALLOC_SRC) -o $@ $(LDFLAGS)

$(BUILD_DIR)/small: small.c $(MALLOC_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) small.c $(MALLOC_SRC) -o $@ $(LDFLAGS)

# Build scored test binaries
$(BUILD_TESTS_DIR)/test%: tests/test%.c $(MALLOC_SRC) | $(BUILD_TESTS_DIR)
	$(CC) $(CFLAGS) tests/test$*.c $(MALLOC_SRC) -o $@ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build smoke tests and scored tests (default)"
	@echo "  smoke    - Build smoke tests (test, self_check, testing, small)"
	@echo "  tests    - Build all scored tests (tests/test1..test20)"
	@echo "  run      - Run all smoke tests"
	@echo "  check    - Run self_check"
	@echo "  score    - Run all scored tests and report score"
	@echo "  clean    - Remove all build artifacts"
	@echo "  help     - Display this help message"
