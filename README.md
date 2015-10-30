# OpenID Connect ID Token verification service

Simple library for verifying signed OpenID Connect ID Tokens.
The library includes a simple WSGI app that can be run as a web service accepting tokens for verification.
 
The web service can be run using any WSGI HTTP Server, for example using `gunicorn`:

    pip install -r requirements.txt
    gunicorn id_token_verify.service:app
    
The web service expects an HTTP POST request containing the following parameters:
 
   * `token` (REQUIRED) the ID Token to verify and unpack
   * `key` (OPTIONAL) symmetric key (client secret), if the ID Token was signed using symmetric key cryptography
   * `jwks` (OPTIONAL) JWKS (JSON Web Key Set), if the provider issuing the ID Token does not support discovery
   
If the signature can be successfully verified the claims of the ID Token will be returned as a JSON document, e.g:

    {
      "exp": 1446287626,
      "iss": "https://example.com",
      "aud": [
          "client"
      ],
      "sub": "sub",
      "nonce": "N0nce",
      "iat": 1446204826.219085
    }

If the signature can not be verified an error will be returned, e.g.:

    {
      "error": "No key that could be used to verify the signature could be found."
    }
