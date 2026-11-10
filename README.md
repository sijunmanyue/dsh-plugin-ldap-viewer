# LDAP Account Viewer

A read-only DeepSeek Harness Web UI plugin for looking up accounts in Active Directory / LDAP. It shows enabled, lock, account-expiry, and password-expiry state in separate columns.

Repository: <https://github.com/sijunmanyue/dsh-plugin-ldap-viewer>

## Features

- Connection settings are read-only until **Edit** is clicked:
  - host and port
  - Base DN and Bind DN
  - bind password (leave blank when saving to keep the current password)
- Exact lookup by:
  - account: `(&(objectClass=user)(sAMAccountName=...))`
  - email: `(&(objectClass=user)(|(mail=...)(userPrincipalName=...)))`
  - mobile: `(&(objectClass=user)(|(mobile=...)(telephoneNumber=...)))`
- Paged results with 10 / 20 / 50 rows per page.
- Columns for account, name, email, mobile, department, and separate statuses:
  - enabled
  - lock state
  - account expiry
  - password valid / expired / must change / never expires / unknown, with expiry time
- Uses the Active Directory attributes `msDS-UserPasswordExpiryTimeComputed`, `msDS-User-Account-Control-Computed`, `pwdLastSet`, `accountExpires`, and `lockoutTime`.
- Uses the RFC 2696 paged-results control and caps a query at 500 entries.

## Install

Clone the repository, then install the directory as a DSH bundle through the Plugin Manager (or `plugin_manager install_bundle` with the absolute directory path):

```bash
git clone https://github.com/sijunmanyue/dsh-plugin-ldap-viewer.git
```

```text
plugin_manager install_bundle
  target = <absolute path to this directory>
```

Refresh the Web page after installation; an **LDAP Account Viewer** icon appears in the left sidebar.

## Configuration and password

- Non-secret connection settings are stored in:

  ```text
  %DSH_HOME%\ldap-viewer\config.json
  ```

  Without `DSH_HOME`, the path is `%USERPROFILE%\.dsh\ldap-viewer\config.json`.

- The bind password is stored through the Harness credential service under `LDAP_VIEWER_PASSWORD`. The page only shows whether a password is configured; it never renders the password.
- If the credential store has no password, the Host falls back to these environment variables:
  - `LDAP_VIEWER_PASSWORD`
  - `LDAP_PASSWORD`

## Example values

These are placeholders only. Replace them with your directory's values in the plugin's configuration section:

```text
host    = ldap.example.com
port    = 389
baseDn  = DC=example,DC=com
bindDn  = CN=service-account,CN=Users,DC=example,DC=com
```

## Security boundary

- The HTTP route accepts loopback requests only.
- The page performs read-only LDAP searches and never modifies the directory.
- Query values are escaped per RFC 4515; the query type is a fixed enum and arbitrary filters are not concatenated.
- Results do not include sensitive attributes such as `userPassword`.
- The plugin uses plain LDAP (default port 389); LDAPS is not configured.

## Files

- `index.js`: Host half; configuration, credentials, HTTP route, and account-state calculations.
- `ldap.js`: dependency-free LDAPv3 client (simple bind, subtree search, paged-results control).
- `client.js`: Web page with configuration card, query form, result table, and pagination.
- `test/mock-ldap.js`: local mock LDAP server for manual verification; not part of the installed bundle.
- `locale/`: Plugin Manager title and description.

## License

MIT. See [LICENSE](LICENSE).
