import pexpect

def send_query(digdoc_cmd, dig_cmd, description):
    """Run a test query with digdoc and dig, compare outputs."""
    # Run digdoc command
    client_child = pexpect.spawn(digdoc_cmd)
    client_child.expect(pexpect.EOF)
    client_output = client_child.before.decode('utf-8')

    # Run dig command
    dig_child = pexpect.spawn(dig_cmd)
    dig_child.expect(pexpect.EOF)
    dig_output = dig_child.before.decode('utf-8')

    # Check if dig output is contained in digdoc output
    dig_lines = dig_output.strip().split('\n')

    return {"client": client_output, "dig": dig_lines}

class TestClass:
    a_record_result = ""

    def test_a_record(self):
        result_dict = send_query("../digdoc @127.0.0.1 agdsn.de A -p 8000", "dig @1.1.1.1 agdsn.de A +short", "Testing A record")
        for line in result_dict.get('dig'):
            TestClass.a_record_result = line
            assert line in result_dict.get('client')

    def test_aaaa_record(self):
        result_dict = send_query("../digdoc @127.0.0.1 ftp.agdsn.de AAAA -p 8000", "dig @1.1.1.1 ftp.agdsn.de AAAA +short", "Testing AAAA record")
        for line in result_dict.get('dig'):
            assert line in result_dict.get('client')

    def test_ptr_record(self):
        segments = TestClass.a_record_result.split(".")
        reversed_segments = segments[::-1]
        reversed_ip = ".".join(reversed_segments)
        result_dict = send_query(f"../digdoc @127.0.0.1 {reversed_ip}.in-addr.arpa PTR -p 8000", f"dig @1.1.1.1 -x {reversed_ip} +short", "Testing PTR record")
        for line in result_dict.get('dig'):
            assert line in result_dict.get('client')

    def test_txt_record(self):
        result_dict = send_query("../digdoc @127.0.0.1 agdsn.de TXT -p 8000", "dig @1.1.1.1 agdsn.de TXT +short", "Testing TXT record")
        for line in result_dict.get('dig'):
            assert line in result_dict.get('client')

    def test_mx_record(self):
        result_dict = send_query("../digdoc @127.0.0.1 agdsn.de MX -p 8000", "dig @1.1.1.1 agdsn.de MX +short", "Testing MX record")
        for line in result_dict.get('dig'):
            assert line in result_dict.get('client')

    def test_ns_record(self):
        result_dict = send_query("../digdoc @127.0.0.1 agdsn.de NS -p 8000", "dig @1.1.1.1 agdsn.de NS +short", "Testing NS record")
        for line in result_dict.get('dig'):
            assert line in result_dict.get('client')