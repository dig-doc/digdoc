#!/bin/bash

# Specify the source file
SOURCE_FILE="main.c"
OUTPUT_BINARY="digdoc"
TEST_SERVER_SOURCE="testing/local_test_server.c"
TEST_SERVER_BINARY="testing/local_test_server"
VENV_DIR=".venv"
TEST_LOCALLY="${TEST_LOCALLY:-0}"
VERBOSE="${VERBOSE:-0}"
REQUIRED_PACKAGES=("pytest" "pexpect")

if [ "$VERBOSE" -eq "1" ]; then
  set -x
fi

# Check if the binary exists
if [ -f "$OUTPUT_BINARY" ]; then
    echo "Binary '$OUTPUT_BINARY' is already present."
else
    echo "Binary '$OUTPUT_BINARY' not found. Attempting to build..."

    # Check if the source file exists
    if [ -f "$SOURCE_FILE" ]; then
        # Compile the source file
        if [ "$VERBOSE" -eq "1" ]; then
          cmake -DCMAKE_VERBOSE_MAKEFILE=ON .
        else
          cmake .
        fi

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

# If test shall run locally, check if the mock server exists

if [ "$TEST_LOCALLY" -eq "1" ]; then
  if [ -f "$TEST_SERVER_BINARY" ]; then
      echo "Binary '$TEST_SERVER_BINARY' is already present."
  else
      echo "Binary '$TEST_SERVER_BINARY' not found. Attempting to build..."

      # Check if the source file exists
      if [ -f "$TEST_SERVER_SOURCE" ]; then
          # Compile the source file
          if [ "$VERBOSE" -eq "1" ]; then
              cmake -DLOCAL_TESTING=ON -DCMAKE_VERBOSE_MAKEFILE=ON .
          else
              cmake -DLOCAL_TESTING=ON .
          fi

          make

          # Check if compilation was successful
          if [ $? -eq 0 ]; then
              echo "Build successful. '$TEST_SERVER_BINARY' is ready."
          else
              echo "Build failed. Please check your source code for errors."
              exit 1
          fi
      else
          echo "Source file '$TEST_SERVER_SOURCE' not found. Cannot build the binary."
          exit 1
      fi
  fi
fi

# Check if a virtual environment is already activated
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "No virtual environment is activated."

    # Check if the venv directory exists
    if [[ ! -d "$VENV_DIR" ]]; then
        echo "Virtual environment directory '$VENV_DIR' not found. Creating one..."

        # Create the virtual environment
        if [ "$VERBOSE" -eq "1" ]; then
            python3 -v -m venv "$VENV_DIR"
        else
            python3 -m venv "$VENV_DIR"
        fi

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
else
    echo "Virtual environment is already activated: $VIRTUAL_ENV"
fi

if ! pip show "aiodnsprox" > /dev/null 2>&1; then
    echo "aiodnsprox not installed. To install it, run: pip install git+https://github.com/anr-bmbf-pivot/aiodnsprox/"
    exit 1
fi

for PACKAGE in "${REQUIRED_PACKAGES[@]}"; do
    if ! pip show "$PACKAGE" > /dev/null 2>&1; then
        echo "$PACKAGE not installed. To install missing packages, run: pip install -r testing/requirements.txt"
        exit 1
    fi
done

if [ "$TEST_LOCALLY" -eq 1 ]; then
    if [ "$VERBOSE" -eq "1" ]; then
        ./local_test_server > testing/local_test_server.txt 2>&1 &
        aiodns-proxy --coap 127.0.0.1 8000 --upstream-dns 127.0.0.2 8000 --dtls-credentials "" "" -v DEBUG> testing/aiodnsprox.txt 2>&1 &
    else
        ./local_test_server > /dev/null 2>&1 &
        aiodns-proxy --coap 127.0.0.1 8000 --upstream-dns 127.0.0.2 8000 --dtls-credentials "" ""> /dev/null 2>&1 &
    fi
else
    if [ "$VERBOSE" -eq "1" ]; then
        aiodns-proxy --coap 127.0.0.1 8000 --upstream-dns 1.1.1.1 --dtls-credentials "" "" -v DEBUG> testing/aiodnsprox.txt 2>&1 &
    else
        aiodns-proxy --coap 127.0.0.1 8000 --upstream-dns 1.1.1.1 --dtls-credentials "" ""> /dev/null 2>&1 &
    fi
fi

sleep 3

cd testing

if [ "$TEST_LOCALLY" -eq 1 ]; then
    pytest -s --ip="127.0.0.2 -p 8000"
else
    pytest -s
fi

exit_status=$?

pkill aiodns-proxy
pkill -f local_test_server

exit $exit_status