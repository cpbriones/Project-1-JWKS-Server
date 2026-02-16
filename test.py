""" Cristobal Briones cpb0128
CSCE 3550 Project 1: test suite for JWKS Server
"""

from fastapi.testclient import TestClient
from project_1 import app
import jwt

client = TestClient(app)

# send get request and check expected keys
def test_jwks_handler_returns_unexpired_keys():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    
    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == "good-key-1"


# send post request and check kid is good key
def test_auth_handler_unexpired():
    response = client.post("/auth")
    assert response.status_code == 200
    token = response.text
    
    # Decode the unverified header
    headers = jwt.get_unverified_header(token)
    assert headers["kid"] == "good-key-1"

# send post request to check kid is expired key
def test_auth_handler_expired():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    token = response.text
    
    # Decode the unverified header
    headers = jwt.get_unverified_header(token)
    assert headers["kid"] == "bad-key-1"