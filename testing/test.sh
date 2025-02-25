#!/bin/bash

# Specify the source file
SOURCE_FILE="main.c"
OUTPUT_BINARY="digdoc"
VENV_DIR=".venv"

# Check if the binary exists
if [ -f "$OUTPUT_BINARY" ]; then
    echo "Binary '$OUTPUT_BINARY' is already present."
else
    echo "Binary '$OUTPUT_BINARY' not found. Attempting to build..."

    # Check if the source file exists
    if [ -f "$SOURCE_FILE" ]; then
        # Compile the source file
        cmake .
        make

        # Check if compilation was successful
        if [ $? -eq 0 ]; then
            echo "Build successful. '$OUTPUT_BINARY' is ready."
        else
            echo "Build failed. Please check your source code for errors."
            exit 1
        fi
    else
        echo "Source file '$SOURCE_FILE' not found. Cannot build the binary."
        exit 1
    fi
fi

# Check if a virtual environment is already activated
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "No virtual environment is activated."

    # Check if the venv directory exists
    if [[ ! -d "$VENV_DIR" ]]; then
        echo "Virtual environment directory '$VENV_DIR' not found. Creating one..."

        # Create the virtual environment
        python3 -m venv "$VENV_DIR"

        if [[ $? -eq 0 ]]; then
            echo "Virtual environment created successfully in '$VENV_DIR'."
        else
            echo "Failed to create virtual environment. Exiting."
            exit 1
        fi
    else
        echo "Virtual environment directory '$VENV_DIR' already exists."
    fi

    # Activate the virtual environment
    source "$VENV_DIR/bin/activate"

    if [[ $? -eq 0 ]]; then
        echo "Virtual environment activated."
    else
        echo "Failed to activate virtual environment. Exiting."
        exit 1
    fi
    pip install git+https://github.com/anr-bmbf-pivot/aiodnsprox/
else
    echo "Virtual environment is already activated: $VIRTUAL_ENV"
fi



pip install pexpect
pip install pytest

# run the aiodns-proxy which expects CoAP (from digdoc), dig directly communicates with the Cloudflare DNS server
aiodns-proxy --coap 127.0.0.1 8000 --upstream-dns 1.1.1.1 --dtls-credentials "" ""> /dev/null 2>&1 &

sleep 3

cd testing

pytest -s
exit_status=$?

pkill aiodns-proxy

exit $exit_status