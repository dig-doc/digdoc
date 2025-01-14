# Specify the source file
SOURCE_FILE="main.c"
OUTPUT_BINARY="digdoc"

# Check if the binary exists
if [ -f "$OUTPUT_BINARY" ]; then
    echo "Binary '$OUTPUT_BINARY' is already present."
else
    echo "Binary '$OUTPUT_BINARY' not found. Attempting to build..."

    # Check if the source file exists
    if [ -f "$SOURCE_FILE" ]; then
        # Compile the source file
        gcc "$SOURCE_FILE" -o "$OUTPUT_BINARY" -L/usr/lib/x86_64-linux-gnu -lcoap-3-gnutls -L/usr/lib/x86_64-linux-gnu -lldns

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

pip install pexpect

aiodns-proxy --coap 127.0.0.1 8000 --upstream-dns 1.1.1.1 --dtls-credentials "" "" > /dev/null 2>&1 &
aiodns-proxy --udp 127.0.0.2 8001 --upstream-dns 1.1.1.1 --dtls-credentials "" "" > /dev/null 2>&1 &

sleep 3

python3 test.py

pkill aiodns-proxy