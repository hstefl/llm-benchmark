#!/bin/bash

# Usage: ./setup_model_outputs.sh 2025-05-27

DATE_DIR="$1"

if [[ -z "$DATE_DIR" ]]; then
  echo "❌ Please provide a date directory under 'out/' (e.g., 2025-05-27)"
  exit 1
fi

BASE_DIR="out/$DATE_DIR/models-outputs"

# List of prompt types
PROMPT_TYPES=(
  "1_zero-shot"
  "2_instructional"
  "3_tool_guided"
  "4_role_based"
  "5_metrics_aware"
)

# List of model names
MODELS=(
  "GPT-4o"
  "GPT-41"
  "GPT-o3"
  "GPT-o4-mini"
  "GPT-o4-mini-high"
  "Claude-Sonnet-4"
  "Gemini-2.5-flash"
  "Gemini-2.5-pro-preview"
)

# Loop over all prompt types
for PROMPT_TYPE in "${PROMPT_TYPES[@]}"; do
  PROMPT_DIR="$BASE_DIR/$PROMPT_TYPE"
  mkdir -p "$PROMPT_DIR"

  echo "📁 Processing: $PROMPT_TYPE"

  # Loop over models
  for MODEL in "${MODELS[@]}"; do
    MODEL_DIR="$PROMPT_DIR/$MODEL"
    LINK_FILE="$MODEL_DIR/link"
    TEST_FILE="$MODEL_DIR/test_generated.py"

    # Create model directory if it doesn't exist
    if [[ ! -d "$MODEL_DIR" ]]; then
      echo "Creating directory: $MODEL_DIR"
      mkdir -p "$MODEL_DIR"
    fi

    # Create 'link' if missing
    if [[ ! -f "$LINK_FILE" ]]; then
      echo "Creating file: $LINK_FILE"
      touch "$LINK_FILE"
    fi

    # Create 'test_generated.py' if missing
    if [[ ! -f "$TEST_FILE" ]]; then
      echo "Creating file: $TEST_FILE"
      touch "$TEST_FILE"
    fi
  done

  echo "✅ Done: $PROMPT_TYPE"
  echo
done

echo "🎉 All directories and files set up under: out/$DATE_DIR/models-outputs/"
