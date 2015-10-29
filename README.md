Simple library for verifying signed OpenID Connect ID Tokens.
The library includes a simple WSGI app that can be run as a web service accepting tokens for verification.
 
The web service can be run using any WSGI HTTP Server, for example using `gunicorn`:

    pip install -r requirements.txt
    gunicorn id_token_verify.service:app
    
The web service expects an HTTP POST request containing the following parameters:
 
   * `token` (REQUIRED) the ID Token to verify and unpack
   * `key` (OPTIONAL) symmetric key (client secret), if the ID Token was signed using symmetric key cryptography
   * `jwks` (OPTIONAL) JWKS (JSON Web Key Set), if the provider issuing the ID Token does not support discovery