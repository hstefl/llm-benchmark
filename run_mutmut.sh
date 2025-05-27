#!/usr/bin/env bash

# Exit on error
set -e

# Check if test path argument is given
if [ $# -ne 1 ]; then
    echo "Usage: $0 path/to/test_generated.py"
    exit 1
fi

TEST_PATH="$1"

# Absolute paths
MAIN_SRC="in/app/main.py"
MAIN_LINK="main.py"
TEST_LINK="test_generated.py"
MUTANTS_DIR="mutants"

# Check if test file exists
if [ ! -f "$TEST_PATH" ]; then
    echo "Error: test file does not exist: $TEST_PATH"
    exit 1
fi

# Cleanup
[ -L "$MAIN_LINK" ] && rm "$MAIN_LINK"
[ -f "$MAIN_LINK" ] && rm "$MAIN_LINK"
[ -L "$TEST_LINK" ] && rm "$TEST_LINK"
[ -f "$TEST_LINK" ] && rm "$TEST_LINK"
[ -d "$MUTANTS_DIR" ] && rm -rf "$MUTANTS_DIR"

# Create symlinks
ln -s "$MAIN_SRC" "$MAIN_LINK"
ln -s "$TEST_PATH" "$TEST_LINK"

echo "Linked: $MAIN_LINK → $MAIN_SRC"
echo "Linked: $TEST_LINK → $TEST_PATH"

# Run mutmut
mutmut run
