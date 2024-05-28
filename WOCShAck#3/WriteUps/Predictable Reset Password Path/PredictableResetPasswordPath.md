## Description
Any user can reset any other user's password by predicting the reset URL, which is always in the format: `http://8em80nvd.3xploit.me/reset_password/{MD5_hash_of_the_account_username}`.

## Exploitation
1. **Identify a username**: Find an existing username (e.g., from the tutorial list).
2. **Generate the MD5 hash of the username**: Use an MD5 hashing tool to hash the username.
3. **Construct the reset URL**: Append the MD5 hash to `http://8em80nvd.3xploit.me/reset_password/`.
4. **Access the URL**: Visit the constructed URL to reset the password.

## PoC
1. **Identify the username to target**: For this example, we will use "admin".
2. **Generate the MD5 hash for "admin"**:
   ```bash
   echo -n "admin" | md5sum
   ```
   The resulting hash is `21232f297a57a5a743894a0e4a801fc3`.
3. **Construct the reset URL**: 
   ```
   http://8em80nvd.3xploit.me/reset_password/21232f297a57a5a743894a0e4a801fc3
   ```
4. **Visit the URL**: By accessing this URL, we can reset the "admin" password.

## Risk
This vulnerability allows any user to compromise any account, including administrative accounts, by resetting their passwords.

## Remediation
To secure the password reset process:
1. **Generate a random and unique token for each password reset request**: Instead of using a predictable MD5 hash of the username, generate a unique, random token for each password reset request.
2. **Expire the reset tokens**: Ensure that these tokens are time-bound and expire after a short period.
3. **Tie the tokens to specific requests**: Link the token to a specific password reset request and validate it before allowing a password reset.
4. **Use secure hash functions**: Ensure any hashing mechanism used is cryptographically secure and avoid exposing internal data like usernames in URLs.

By implementing these measures, you can prevent unauthorized password resets and enhance the security of user accounts.

# Author
INSA_CVL_Pastis_Tempest