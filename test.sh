#! /bin/bash
pytest --cov=zappa --durations=10

# For a specific test:
# pytest tests/tests.py::TestZappa::test_lets_encrypt_sanity -s
