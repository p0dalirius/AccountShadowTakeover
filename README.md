# AccountShadowTakeover



## Workflow

Requirements :
 - Knowledge of the default password attrributed to new users in the domain.
 - PKINIT ?

 1. Wait for a new User account to be created
 2. Connect with the default password
 3. Add `msDS-KeyCredentialLink` field to the account
 4. Goto 1
