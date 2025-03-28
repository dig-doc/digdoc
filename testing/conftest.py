def pytest_addoption(parser):
    """Add custom command line option."""
    parser.addoption(
        "--ip", action="store", default="1.1.1.1", help="IP address to use for dig command"
    )
    parser.addoption(
        "--v", action="store", default="0", help="Print verbose output"
    )