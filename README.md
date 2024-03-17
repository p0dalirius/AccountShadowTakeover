![](./.github/banner.png)

<p align="center">
    A python script to automatically add a KeyCredentialLink to newly created users, by quickly connecting to them with default credentials.
    <br>
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/Hashes-Harvester">
    <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
    <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
    <br>
</p>

> [!WARNING]
> The idea is fun, but does not work for now. It will maybe work one day when a new technique to allow a user to write its own `msDS-KeyCredentialLink` attribute is found.

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
