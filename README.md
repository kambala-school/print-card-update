# print-card-update
Simple web app for ICT staff to update the ID card for a user in PaperCut, Active Directory, and RollCall

## Environment Variables
Container variables
```
TZ = 'Australia/Sydney'
FLASK_PORT = '5000'
```
Active Directory connection details
```
LDAP_SERVER = 'ldap://host.domain.com'
LDAP_USER = 'CN=Service Account,OU=Users,DC=domain,DC=com'
LDAP_PASSWORD = 'passwordString'
LDAP_SEARCH_BASE = 'OU=Users,DC=domain,DC=com'
```
PaperCut XML API details\
https://www.papercut.com/help/manuals/ng-mf/common/tools-web-services/ \
The client address will need to be whitelisted with advanced config property "auth.webservices.allowed-addresses" \
The password is defined in advanced config property "auth.webservices.auth-token"
```
PAPERCUT_HOST = 'https://papercut.domain.com:9192/rpc/api/xmlrpc'
PAPERCUT_AUTH = 'passwordString'
```
RollCall API details\
The API endpoint for updating student card details in the RollCall system. Use the LDAP group so that it only attempts to update student accounts, not staff.
```
ROLLCALL_API_URL = 'https://schoolcode.rollcall.com.au/api/update_card'
ROLLCALL_TOKEN = 'your-rollcall-token-here'
LDAP_STUDENT_GROUP = 'CN=AllStudents,OU=Groups,DC=school,DC=nsw,DC=edu,DC=au'
```
OpenID IdP details
```
OAUTH_CLIENT_ID=your_client_id_here
OAUTH_CLIENT_SECRET=your_client_secret_here
OAUTH_ISSUER=https://issuer/
OAUTH_METADATA_URL=https://metadata/
```

## Features
- Updates user's card ID number in Active Directory (pager attribute)
- Updates user's primary card number in PaperCut
- Updates user's card code in RollCall system using employeeNumber from Active Directory
- OAuth authentication integration
- Comprehensive error handling with user-friendly messages