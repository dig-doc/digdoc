. .venv/bin/activate;

pip install pexpect

aiodns-proxy --coap 127.0.0.1 8000 --upstream-dns 1.1.1.1 --dtls-credentials "" "" > /dev/null 2>&1 &
aiodns-proxy --udp 127.0.0.2 8001 --upstream-dns 1.1.1.1 --dtls-credentials "" "" > /dev/null 2>&1 &

sleep 1

python3 test.py

pkill aiodns-proxy