import pexpect

def test_query(digdoc_cmd, dig_cmd, description):
    """Run a test query with digdoc and dig, compare outputs."""
    # Run digdoc command
    client_child = pexpect.spawn(digdoc_cmd)
    client_child.expect(pexpect.EOF)
    client_output = client_child.before.decode('utf-8')

    # Run dig command
    dig_child = pexpect.spawn(dig_cmd)
    dig_child.expect(pexpect.EOF)
    dig_output = dig_child.before.decode('utf-8')

    # Print results
    print(f"\n--------------------------------------------------------\n{description}\n\nDigdoc query:\n{client_output}")
    print("-----")
    print(f"Dig query:\n\n{dig_output}")

    # Check if dig output is contained in digdoc output
    dig_lines = dig_output.strip().split('\n')
    contains = all(line in client_output for line in dig_lines)

    if contains:
        print("-----\n\033[32mTest passed!\033[0m\n--------------------------------------------------------")
    else:
        for line in dig_lines:
            if line not in client_output:
                print(f"Not found: {line}")
        print("-----\n\033[31mTest failed!\033[0m\n--------------------------------------------------------")


# Define test cases
test_cases = [
    ("./digdoc @127.0.0.1 agdsn.de A -p 8000", "dig @1.1.1.1 agdsn.de A +short", "Testing A record"),
    ("./digdoc @127.0.0.1 ftp.agdsn.de AAAA -p 8000", "dig @1.1.1.1 ftp.agdsn.de AAAA +short", "Testing AAAA record"),
    ("./digdoc @127.0.0.1 130.119.76.141.in-addr.arpa PTR -p 8000", "dig @1.1.1.1 -x 141.76.119.130 +short", "Testing PTR record"),
    ("./digdoc @127.0.0.1 agdsn.de TXT -p 8000", "dig @1.1.1.1 agdsn.de TXT +short", "Testing TXT record"),
    ("./digdoc @127.0.0.1 agdsn.de MX -p 8000", "dig @1.1.1.1 agdsn.de MX +short", "Testing MX record"),
    ("./digdoc @127.0.0.1 agdsn.de NS -p 8000", "dig @1.1.1.1 agdsn.de NS +short", "Testing NS record"),
]

# Run tests
for digdoc_cmd, dig_cmd, description in test_cases:
    test_query(digdoc_cmd, dig_cmd, description)
