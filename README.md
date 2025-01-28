# digdoc

*digdoc* is a lightweight command-line tool written in C that acts as a DNS-over-CoAP (DoC) client. Since most common DNS servers do not natively support CoAP, digdoc currently uses the aiodns-proxy project to translate CoAP packets into standard UDP-based DNS queries.

Note: An API documentation for implementation details can be found at `./sphinx/build/index.html`

## Prerequisites:

- basic building tools: python3.12-venv, autoconf
- install libraries: `sudo apt install libcoap3-dev libldns-dev`
- create a python virtual environment: `python -m venv .venv`
- activate the venv: `source .venv/bin/activate`
- install aiodns-proxy: `pip install git+https://github.com/anr-bmbf-pivot/aiodnsprox/`

### Build the project
- open project root folder
- generate build-files `cmake .`
- build `make`

### Running Tests
`./testing/test.sh`

Note: Since testing for hardcoded IP-addresses is not meaningful, we assume that the DNS lookup utility *dig* correctly works and compare its results with the results of *digdoc*. 

## run aiodns-proxy:
run the aiodns-proxy using the CoAP protocol for reaching e.g. via port 8000 the Cloudflare DNS server:

`aiodns-proxy --coap localhost 8000 --upstream-dns 1.1.1.1 --dtls-credentials "" ""`

Note: for using IPv6, replace `localhost` with `::1`

## run didoc:
in a second terminal, digdoc can be used e.g. like that:

` ./digdoc @127.0.0.1 example.org A`

Note:
- the default record type is `A` and the default domain is `example.org`
- the default port is `8000`, if aiodns-proxy uses another, e.g. port `1234`, add this here as an argument:

` ./digdoc @127.0.0.1 example.org A -p 1234`

- for using IPv6, replace `@127.0.0.1` with `"@[::1]"`
