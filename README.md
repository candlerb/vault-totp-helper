**NOTE:** This code is derived from [hashicorp/vault-ssh-helper](https://github.com/hashicorp/vault)
and has the same licence.

vault-totp-helper
=================

`vault-totp-helper` allows machines to verify TOTP tokens against a
Hashicorp Vault server.  For example, it can be used to replace static sudo
passwords, or as a second factor along with SSH public key logins. 
Authenticating against Vault avoids having to distribute TOTP keys to the
hosts themselves.

Each host must have its configuration changed to enable TOTP validation
at the desired point(s) in its PAM stack.

`vault-totp-helper` is not a PAM module, but it does the job of one. 
`vault-totp-helper`'s binary is run as an external command using
`pam_exec.so` with access to the entered TOTP response.  Successful
execution and exit of this command is a PAM 'requisite' for authentication
to be successful.  If the OTP is not validated, the binary exits with a
non-zero status and authentication fails.

PAM modules are generally shared object files; rather than writing and
maintaining a PAM module in C, `vault-totp-helper` is written in Go and invoked
as an external binary. This allows `vault-totp-helper` to be contained within
one code base with known, testable behavior. It also allows other
authentication systems that are not PAM-based to invoke `vault-totp-helper` and
take advantage of its capabilities.

Usage
-----
`vault-totp-helper [options]`

### Options

|Option       |Description|
|-------------|-----------|
|`config`     |The path to the configuration file. Configuration options are detailed below.
|`dev`        |`vault-totp-helper` communicates with Vault with TLS disabled. This is NOT recommended for production use. Use with caution.

Build and Install
-----------------

```
go mod tidy
go build .
sudo cp vault-totp-helper /usr/local/bin/
```

Follow the instructions below to modify your PAM configuration and/or SSH
server configuration.  Check if `vault-totp-helper` is installed and
configured correctly and also is able to communicate with Vault server
properly.  Before verifying `vault-totp-helper`, make sure that the Vault
server is up and running and it has mounted the TOTP secrets engine.  Also,
make sure that the mount path of the TOTP backend is properly updated in
`vault-totp-helper`'s config file, if required.

Configuring Vault for TOTP
--------------------------

Enable the secrets engine:

```
vault secrets enable totp   # [-path=some-other-path]
```

Each user will need a secret TOTP key in Vault, where the key name is equal
to their PAM username (Unix login name):

```
vault write totp/keys/ubuntu generate=true issuer=Vault account_name=ubuntu
```

`issuer` and `account_name` can be anything. The user's authenticator
app will typically label the key as "issuer (account_name)"

This returns a QR code (base64-encoded PNG) and a URL, which you can give to
the user to put in their authenticator app.  Both are equivalent, and
contain the generated secret.

You can test TOTP by generating a code and (quickly) validating it, both
from Vault:

```
$ vault read totp/code/ubuntu
Key     Value
---     -----
code    793232

$ vault write totp/code/ubuntu code=886531
Key      Value
---      -----
valid    false

$ vault write totp/code/ubuntu code=793232
Key      Value
---      -----
valid    true
```

Note that generating codes is not currently available via the
[web UI](https://github.com/hashicorp/vault/issues/12698).

For more details, see the documentation of the
[TOTP secrets engine](https://www.vaultproject.io/docs/secrets/totp)
and the [TOTP API](https://www.vaultproject.io/api/secret/totp).

AppRole for TOTP validation
---------------------------

`vault-totp-helper` needs to be able to access the Vault API to validate
TOTP responses.  Unless the host already has a Vault token which it keeps
fresh via some other background process, you will need to create an
[AppRole](https://www.vaultproject.io/docs/auth/approle) and secret:

```
vault auth enable approle

vault policy write totp-validate - <<"EOH"
path "totp/code/*"
{
  capabilities = ["update"]
}
EOH

vault write auth/approle/role/totp-validate \
    policies=totp-validate \
    token_no_default_policy=true \
    token_ttl=2m \
    token_max_ttl=2m \
    token_num_uses=0 \
    token_type=batch

vault write -f auth/approle/role/totp-validate/secret-id \
  # [metadata=host=www1.example.com] [cidr_list="192.0.2.1/32,2001:db8::1/128"]
```

Note the returned `secret_id`.  Best practice would be to create a separate
secret for each host which does TOTP validation, bound to its IP - whether
or not you do so is up to you.

You can test this manually:

```
SECRET_ID="<secret_id>"

ROLE_ID=$(vault read -field=role_id auth/approle/role/totp-validate/role-id)

APP_TOKEN=$(vault write -field=token auth/approle/login role_id=$ROLE_ID secret_id=$SECRET_ID)

VAULT_TOKEN=$APP_TOKEN vault write totp/code/ubuntu code=886531
```

When you first use the AppRole it creates an entity with the `role_id` as
its alias name.  If you wish, you can locate this entity in the Vault web UI
(select "Entities", "Lookup by Alias Name") and change the entity name to
something more memorable like `AppRole totp-validate"

`vault-totp-helper` Configuration
---------------------------------
**[Note]: This configuration is applicable for Ubuntu 20.04. SSH/PAM
configurations differ with each platform and distribution.**

`vault-totp-helper`'s configuration is written in [HashiCorp Configuration
Language (HCL)](https://github.com/hashicorp/hcl).  By proxy, this means that
`vault-totp-helper`'s configuration is JSON-compatible. For more information,
please see the [HCL Specification](https://github.com/hashicorp/hcl).

### Properties
|Property           |Description|
|-------------------|-----------|
|`vault_addr`       |[Required] Address of the Vault server.
|`totp_mount_point` |Mount point of TOTP secret backend in Vault server (defaults to "totp")
|`namespace`        |Namespace of the SSH mount. (Vault Enterprise only)
|`ca_cert`          |Path of a PEM-encoded CA certificate file used to verify the Vault server's TLS certificate. `-dev` mode ignores this value.
|`ca_path`          |Path to directory of PEM-encoded CA certificate files used to verify the Vault server's TLS certificate. `-dev` mode ignores this value.
|`tls_skip_verify`  |Skip TLS certificate verification. Use with caution.
|`token_file`       |Path to file containing pre-existing token
|`role_id`          |AppRole role_id for verifying tokens
|`secret_id`        |secret_id: value provided directly inline
|`secret_file`      |secret_id: path to file containing value
|`secret_env`       |secret_id: name of environment variable containing value

If you provide `token_file` then this must point to a file containing a
pre-existing token to use. This token must be renewed externally.

If you provide `role_id` then you must also include one of `secret_id`,
`secret_file` or `secret_env`.  If you use `secret_id` then ensure that the
permissions are set so that normal users cannot read the configuration file.

If no authentication options are set, the Vault client will fall back to its
default of using the `VAULT_TOKEN` environment variable.

Sample `config.hcl`:

```hcl
vault_addr = "https://vault.example.com:8200"
totp_mount_point = "totp"
namespace = "my_namespace"
ca_cert = "/etc/vault-totp-helper.d/vault.crt"
tls_skip_verify = false
role_id = "d2e6e8f2-1091-477c-a255-603634ea4acd"
secret_id = "5f134c14-de70-404c-aabf-406f4c799419"
```

You can test `vault-totp-helper` standalone:

```
$ echo 123456 | PAM_USER=ubuntu /usr/local/bin/vault-totp-helper -config=config.hcl
2022/02/16 13:07:48 [INFO] using TOTP mount point: totp
2022/02/16 13:07:48 [INFO] using namespace:
2022/02/16 13:07:50 [ERROR] Response is invalid
$ 
```

PAM Configuration (sudo)
------------------------
To use TOTP for sudo password, modify the `/etc/pam.d/sudo` file as follows;
each option will be explained below.

```
#@include common-auth
auth [success=1 default=ignore] pam_exec.so quiet expose_authtok log=/tmp/vault-totp.log /usr/local/bin/vault-totp-helper -config=/etc/vault-totp-helper.d/config.hcl
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
```

First, the previous authentication mechanism `common-auth`, which is the
standard Linux authentication module, is commented out, in favor of using our
custom configuration.

Next the authentication configuration for `vault-totp-helper` is set.

|Keyword                     |Description |
|----------------------------|------------|
|`auth`                      |PAM type that the configuration applies to.
|`[success=1 default=ignore]`|If the external command succeeds, skip the next rule; otherwise continue.
|`pam_exec.so`               |PAM module that runs an external command (`vault-totp-helper`).
|`quiet`                     |Suppress the exit status of `vault-totp-helper` from being displayed.
|`expose_authtok`            |Binary can read the password from stdin.
|`log`                       |Path to `vault-totp-helper`'s log file.
|`vault-totp-helper`         |Absolute path to `vault-totp-helper`'s binary.
|`-config`                   |The path to `vault-totp-helper`'s config file.

The third line fails the authentication if the TOTP could not be verified;
it will cause sudo to prompt for another attempt, to its maximum of 3.

The final line marks the authentication as successful; the pam_exec.so line
jumps to here if the external command succeeds.

### Credential caching

In many OSes the `sudo` application is configured by default to cache a
successful authentication for 5 minutes.  Use `sudo -k` to invalidate the
cache and force another authentication.

### Limitations

The password prompt does not say that a TOTP response is expected:

```
[sudo] password for ubuntu:
```

You can override this in the `sudoers` configuration file, e.g.

```
Defaults passprompt="[sudo] TOTP password for %u: ",pwfeedback
```

Public key or certificate authentication with TOTP as 2FA
---------------------------------------------------------

It is possible to use this module for second-factor authentication alongside
public key authentication.

BEWARE: you must be careful to configure SSHD to require *both* publickey
*and* PAM, otherwise the TOTP PAM response alone will be sufficient!!!

### SSHD Configuration

Modify the `/etc/ssh/sshd_config` file as follows, to require both types of
authentication to succeed (the items must be comma-separated, not
space-separated)

```
AuthenticationMethods publickey,keyboard-interactive:pam
```

Also check the following settings.  For many distributions these are the
default options; you may not need to set them explicitly but should verify
their values if not.

```
ChallengeResponseAuthentication yes
UsePAM yes
PasswordAuthentication no
```

If you want to bypass the 2FA requirement when connecting from a trusted
source, e.g. VPN, then add this to the *end* of the config:

```
Match address 10.0.0.0/8,192.168.0.0/16
AuthenticationMethods publickey
```

|Option                               |Description |
|-------------------------------------|------------|
|`ChallengeResponseAuthentication yes`|[Required] Enable challenge response (keyboard-interactive) authentication.
|`UsePAM yes`                         |[Required] Enable PAM authentication modules.
|`PasswordAuthentication no`          |[Required] Disable password authentication.
|`AuthenticationMethods ...`          |[Required] Define which methods must be completed to accept the login.
|`Match address ...`                  |Subsequent settings only apply to connections from these IPs

### PAM configuration

Once you are sure that SSHD is requiring *both* public key or certificate
*and* PAM, then make the same configuration change as described above for
sudo, except in the `/etc/pam.d/sshd` file.
