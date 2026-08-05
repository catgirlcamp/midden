# Accounts And Tokens

Accounts let users own files and pastes, search their items, manage visibility and expiry, create API tokens, link OIDC identities, and configure security features.

## Account Page

Open:

```text
/account
```

The account page shows owned files, owned pastes, API tokens when the API is enabled, password controls for local accounts, email verification state, two-factor state, and OIDC linking when available.

## Bulk Item Actions

Account-owned files and pastes support bulk actions:

- Delete selected items.
- Set visibility.
- Set expiry.

Authorization still checks ownership and delete policy.

## API Tokens

API tokens start with `mdd_` and are shown once at creation time. Store them securely.

Token creation requires at least one scope. Operators can configure default and maximum TTLs:

```toml
[tokens]
default_ttl_seconds = 2592000
max_ttl_seconds = 31536000
```

Completing a password reset revokes every token on the account, so anything automated against Midden needs a fresh token afterwards. Changing your password from the account page leaves tokens working.

## Sessions

Changing your password signs out your other sessions and keeps the one you are using. A password reset signs out every session, including the one that performed it — you are signed back in immediately as part of the reset.

## Two-Factor Authentication

Two-factor setup uses emailed challenge codes. SMTP must be configured and working.

## OIDC Linking

When OIDC is enabled, signed-in users can link an OIDC identity from the account page.
