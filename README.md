# Project-1-JWKS-Server
RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.


# Installation
1. Clone/download project
2. Create virtual environment
   
`python -m venv .venv`

4. Activate virtual environment (windows)
   
`.venv\Scripts\activate`

6. Install dependencies
   
`pip install fastapi uvicorn PyJWT cryptography httpx pytest pytest-cov`

# Testing
1. start server

`python project_1.py`

3. run test suite 

`pytest --cov=project_1 test.py`

4. gradebot

`./gradebot.exe project-1 --run="python project_1.py"`
