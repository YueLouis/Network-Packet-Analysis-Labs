#!/bin/bash

# Lab 3.2: Setup and Run Script for Linux/Mac

echo "========================================"
echo "Lab 3.2: AI-Powered Dissectors"
echo "========================================"
echo ""

# Check if API key is set
if [ -z "$GROQ_API_KEY" ]; then
    echo "ERROR: GROQ_API_KEY environment variable not set!"
    echo ""
    echo "Please set it first:"
    echo "  export GROQ_API_KEY=your_key_here"
    echo ""
    echo "Or add it to your ~/.bashrc or ~/.zshrc:"
    echo "  echo 'export GROQ_API_KEY=your_key_here' >> ~/.bashrc"
    echo ""
    echo "Get a free API key from: https://console.groq.com/keys"
    exit 1
fi

echo "Running AI Dissector Examples..."
echo ""
cd examples
python3 examples.py
