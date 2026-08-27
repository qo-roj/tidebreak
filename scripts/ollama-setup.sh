# Tidebreak — Ollama Setup Script
# Auto-detects hardware and recommends a model

#!/usr/bin/env bash
set -euo pipefail

echo "🦞 Tidebreak — Ollama Setup"
echo ""

# Check if Ollama is installed
if ! command -v ollama &>/dev/null; then
    echo "Ollama is not installed. Installing..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo ""
fi

# Detect available RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

# Detect GPU
GPU=""
if command -v nvidia-smi &>/dev/null; then
    GPU="nvidia"
    GPU_VRAM_MB=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
    GPU_VRAM_GB=$((GPU_VRAM_MB / 1024))
elif command -v rocm-smi &>/dev/null; then
    GPU="amd"
    GPU_VRAM_GB=$(rocm-smi --showmeminfo vram | awk '/VRAM Total/{print $NF}' | head -1)
    GPU_VRAM_GB=$((GPU_VRAM_GB / 1024))
elif command -v intel_gpu_top &>/dev/null 2>&1 || lspci | grep -q "VGA.*Intel"; then
    GPU="intel"
    GPU_VRAM_GB=0  # Intel iGPU shares system RAM
fi

echo "Detected hardware:"
echo "  RAM: ${TOTAL_RAM_GB} GB"
if [[ -n "$GPU" ]]; then
    echo "  GPU: ${GPU} (${GPU_VRAM_GB:-?} GB VRAM)"
else
    echo "  GPU: none"
fi
echo ""

# Recommend model
recommend_model() {
    if [[ -n "$GPU" && "${GPU_VRAM_GB:-0}" -ge 40 ]]; then
        echo "llama3:70b"
    elif [[ -n "$GPU" && "${GPU_VRAM_GB:-0}" -ge 20 ]]; then
        echo "qwen2.5:14b"
    elif [[ "$TOTAL_RAM_GB" -ge 32 ]]; then
        echo "qwen2.5:14b"
    elif [[ "$TOTAL_RAM_GB" -ge 16 ]]; then
        echo "llama3:8b"
    elif [[ "$TOTAL_RAM_GB" -ge 8 ]]; then
        echo "llama3:8b"
    elif [[ "$TOTAL_RAM_GB" -ge 4 ]]; then
        echo "qwen2.5:3b"
    else
        echo "qwen2.5:1.5b"
    fi
}

MODEL=$(recommend_model)

echo "Recommended model: ${MODEL}"
echo ""
echo "This model will be used by Tidebreak for local-only content processing."
echo "It reads sensitive data locally and produces de-identified summaries"
echo "that can safely be sent to cloud LLM providers."
echo ""

read -p "Pull model '${MODEL}' now? [Y/n] " -r
REPLY=${REPLY:-Y}
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Pulling ${MODEL} (this may take a few minutes)..."
    ollama pull "$MODEL"
    echo ""
    echo "✓ Model '${MODEL}' is ready."
    echo ""
    echo "Configure Tidebreak to use it:"
    echo "  tidebreak config set local.ollama_model ${MODEL}"
else
    echo ""
    echo "Skipped. You can pull it later with: ollama pull ${MODEL}"
fi

echo ""
echo "Ollama is running at http://localhost:11434"
echo "Tidebreak will connect automatically."