#! /bin/bash
pytest tests/ --cov=zappa -v

# For a specific test:
# pytest tests/tests.py::TestZappa::test_lets_encrypt_sanity -s
