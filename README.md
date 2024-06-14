# print-card-update
Simple web app for ICT staff to update the ID card for a user in PaperCut and Active Directory

## Environment Variables
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