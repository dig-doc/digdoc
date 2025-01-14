import pexpect

client_child = pexpect.spawn(f'./digdoc @127.0.0.1 agdsn.de A -p 8000')

client_child.expect(pexpect.EOF)

dig_child = pexpect.spawn(f'dig @127.0.0.2 agdsn.de A -p 8001 +short')

dig_child.expect(pexpect.EOF)

client_output = client_child.before.decode('utf-8')
dig_output = dig_child.before.decode('utf-8')

# Optional: Print full interaction log for debugging
print(client_output)
print("-----")
print(dig_output)

dig_lines = dig_output.strip().split('\n')
contains = True
for line in dig_lines:
    if line not in client_output:
        print(f"Not found: {line}")
        contains = False

if contains:
    print("Test passed!")
else:
    print("Test failed!")
# NS, PTR?, TXT?
client_child = pexpect.spawn(f'./digdoc @127.0.0.1 agdsn.de TXT  -p 8000')

client_child.expect(pexpect.EOF)

dig_child = pexpect.spawn(f'dig @127.0.0.2 agdsn.de TXT -p 8001 +short')

dig_child.expect(pexpect.EOF)

client_output = client_child.before.decode('utf-8')
dig_output = dig_child.before.decode('utf-8')

# Optional: Print full interaction log for debugging
print(client_output)
print("-----")
print(dig_output)

dig_lines = dig_output.strip().split('\n')
contains = True
for line in dig_lines:
    if line not in client_output:
        print(f"Not found: {line}")
        contains = False

if contains:
    print("Test passed!")
else:
    print("Test failed!")

client_child = pexpect.spawn(f'./digdoc @127.0.0.1 agdsn.de MX -p 8000')

client_child.expect(pexpect.EOF)

dig_child = pexpect.spawn(f'dig @127.0.0.2 agdsn.de MX -p 8001 +short')

dig_child.expect(pexpect.EOF)

client_output = client_child.before.decode('utf-8')
dig_output = dig_child.before.decode('utf-8')

# Optional: Print full interaction log for debugging
print(client_output)
print("-----")
print(dig_output)

dig_lines = dig_output.strip().split('\n')
contains = True
for line in dig_lines:
    if line not in client_output:
        print(f"Not found: {line}")
        contains = False

if contains:
    print("Test passed!")
else:
    print("Test failed!")

client_child = pexpect.spawn(f'./digdoc @127.0.0.1 agdsn.de NS -p 8000')

client_child.expect(pexpect.EOF)

dig_child = pexpect.spawn(f'dig @127.0.0.2 agdsn.de NS -p 8001 +short')

dig_child.expect(pexpect.EOF)

client_output = client_child.before.decode('utf-8')
dig_output = dig_child.before.decode('utf-8')

# Optional: Print full interaction log for debugging
print(client_output)
print("-----")
print(dig_output)

dig_lines = dig_output.strip().split('\n')
contains = True
for line in dig_lines:
    if line not in client_output:
        print(f"Not found: {line}")
        contains = False

if contains:
    print("Test passed!")
else:
    print("Test failed!")