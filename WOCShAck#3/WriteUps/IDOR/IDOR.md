# Description
This vulnerability results in a malfunction of the access management for the comment service. It allows a malicious user to delete a comment created by another user without having the rights or any agreement from the author.

# Exploitation
The only information needed for this attack is the ID of the comment to delete. Then, the attacker simply needs to go to the following address:
```
http://vu9piqbr.3xploit.me/delete_tutorial/<id>
```

# Proof of Concept (PoC)
To delete a comment with ID 1, the attacker can use the following URL:
```bash
http://vu9piqbr.3xploit.me/delete_tutorial/1
```

# Risk
This bug alters the intended functionality of your website. It can lead to a potential loss of confidence from your clients, as anyone can delete their comments without permission.

# Remediation
A suitable fix for this vulnerability would be to implement authentication for the delete comment operation. The easiest way to do this in your case is likely to add a check on the JWT token's user field and verify that it matches the author before allowing the deletion.

# Author
2600