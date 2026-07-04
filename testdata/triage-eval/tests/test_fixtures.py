# Deliberately planted fixtures for the appsec triage eval.
# Every finding here is planted and labeled. DO NOT fix.
import pytest
from unittest.mock import Mock, patch

# PLANT(FP): documented example / dummy value, not a live credential
DUMMY_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# PLANT(FP): documented example / dummy value, not a live credential
EXAMPLE_API_TOKEN = "test-token-0000-EXAMPLE"


def test_stub_rejects_dummy_credentials():
    # PLANT(FP): documented example / dummy value, not a live credential
    mock_client = Mock()
    mock_response = Mock()
    mock_response.status_code = 403
    mock_client.post.return_value = mock_response

    # Simulate checking against a stub that rejects these known dummy values
    response = mock_client.post('/auth', json={'key': DUMMY_AWS_ACCESS_KEY, 'token': EXAMPLE_API_TOKEN})
    
    assert response.status_code == 403
