""" Cristobal Briones cpb0128
CSCE 3550 Project 1: JWKS Server
Using python and FastAPI this project implements a jwks server with key expiration and jwt signing.  

"""

import time
from fastapi import FastAPI, Response
import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
import uvicorn

app = FastAPI()

# key storage
keys = {}

# Function to generate RSA key pair and store in keys dictionary
def generate_key(kid: str, is_expired: bool = False) -> None:
    # Generates RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Converts public key to JWK format
    public_key = private_key.public_key()
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    
    # metadata for JWK
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    jwk["kid"] = kid
    
    # sets expiration 1 hour ago or 1 hour in the future
    expiry = time.time() - 3600 if is_expired else time.time() + 3600
    
    # stores private key and jwk
    keys[kid] = {
        "private_key": private_key,
        "jwk": jwk,
        "expiry": expiry
    }

# Initialize keys on startup
generate_key("good-key-1", is_expired=False)
generate_key("bad-key-1", is_expired=True)

@app.get('/.well-known/jwks.json')
@app.get('/jwks')
# Filters out expired keys. returns JSON with valid keys
def jwks_handler():

    # check current time against key expiry and filter out expired keys
    current_time = time.time()
    valid_keys = [k["jwk"] for k in keys.values() if k["expiry"] > current_time]
    
    # return with valid keys
    return {"keys": valid_keys}


@app.post('/auth')
# if expired, return token signed with expired key, else return token signed with valid key
def auth_handler(expired: str | None = None):

    is_expired_req = expired is not None
    current_time = time.time()
    
    selected_kid = None
    
    # Select the appropriate key based on expiration requirement
    for kid, k in keys.items():
        if is_expired_req and k["expiry"] <= current_time:
            selected_kid = kid
            break
        elif not is_expired_req and k["expiry"] > current_time:
            selected_kid = kid
            break
    
    # If no valid key is found, return error
    if not selected_kid:
        return Response(content="No valid key found", media_type="text/plain", status_code=500)
        
    # Get the key data for the selected kid
    key_data = keys[selected_kid]
    
    # Create JWT payload 
    payload = {
        "sub": "mock-user",
        "exp": int(key_data["expiry"]),
        "iat": int(current_time)
    }
    
    # Sign the JWT with the selected key's private key
    token = jwt.encode(
        payload, 
        key_data["private_key"],
        algorithm="RS256", 
        headers={"kid": selected_kid}
    )
    
    # Return raw text string
    return Response(content=token, media_type="text/plain")

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8080)


""" AI Prompts used for development:
These prompts helped me implement the fastapi framework, RSA key generation, JWK conversion, and JWT signing.

fastapi vs flask for jwks server
fastapi jwks server creation
RSA key generation python
Generate RSA key pair in Python using cryptography library
RSA key JWK conversion
to_jwk to return Python dictionary instead of a string
jwt payload python
return jwt as raw text string fastapi
fastapi test client python
python test coverage tools
"""