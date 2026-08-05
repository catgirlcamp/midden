# Authentication

Midden supports local accounts, OIDC login, invite-based or open signup, API tokens, and two-factor email challenges.

## Feature Switches

```toml
[features]
accounts = true
local_login = true
oidc_login = false

[policy]
signup = "disabled"
create_account = "disabled"
```

`accounts` controls account surfaces. `local_login` controls password login and registration affordances. `oidc_login` controls OIDC login routes, but OIDC must also be configured.

## Signup Modes

`policy.signup` accepts:

- `disabled`: no public signup.
- `open`: public registration is available.
- `invite_only`: users need invite tokens created by admins.
- `admin_created`: admins create users manually.

Under `invite_only`, the account and the invite are created together in one transaction: a registration that does not present a valid, unused, unexpired invite creates nothing. Invites carry the role the new account gets, and each one admits exactly one account.

Under `open`, registration requires email verification whenever SMTP is enabled.

## Local Login

Local login uses password hashes stored on users. Owner password recovery is available from the CLI:

```console
midden --config midden.toml owner reset-password --email owner@example.test --password new-password
```

## OIDC Login

```toml
[features]
accounts = true
oidc_login = true

[oidc]
enabled = true
issuer_url = "https://accounts.example.test"
client_id = "midden"
client_secret = "secret"
redirect_url = "https://files.example.test/auth/oidc/callback"
allowed_domains = ["example.test"]
allowed_groups = ["midden-users"]
role_claim = "role"
groups_claim = "groups"

[oidc.role_mappings]
midden-moderators = "moderator"
midden-admins = "admin"
```

OIDC is considered usable only when accounts, the OIDC feature flag, provider config, client credentials, and redirect URL are present. The admin save path rejects settings that would disable local login without a usable OIDC login path.

### Role Mapping

On each login Midden collects the values of `role_claim` and `groups_claim` and takes the highest role any of them maps to in `[oidc.role_mappings]`. That role is written back to the account, except that an owner is never demoted.

If no claim value matches a mapping, the stored role is left alone. The provider has not said anything about this user, so a role assigned with `user set-role` survives their next OIDC login. To manage roles entirely from the provider, map every group that should get elevated access and remove elevated roles there rather than in Midden.

### Email Trust

When an OIDC identity signs in for the first time and an account already exists with the same email address, Midden will adopt that account only if it has no local password **and** the provider reports `email_verified` as true. Providers that let users assert arbitrary addresses would otherwise hand over any matching passwordless account — including an owner created without `--password`.

Accounts newly provisioned by OIDC do not require the claim, since they are bound to the issuer and subject and put no existing account at risk.

## Two-Factor Challenges

Users can enable two-factor authentication from the account page. Midden sends a challenge code by email, so SMTP must be configured for the challenge flow to be usable.

## Password Reset

Reset links are requested at `/auth/password-reset` and expire after one hour.

The request endpoint answers identically whether or not the address has an account, and sends mail in the background so that response time does not reveal the answer either. Nothing about a failed delivery reaches the caller, so watch the logs if users report links not arriving.

Completing a reset is treated as account recovery. It drops every session for the account and revokes all of its API tokens, on the assumption that whoever prompted the reset may still hold them. A password change from the account page is narrower: it signs out the account's other sessions and leaves tokens alone.

## Roles

Roles are ordered:

```text
user < moderator < admin < owner
```

Use the CLI to assign roles:

```console
midden --config midden.toml user set-role --email user@example.test --role moderator
```
