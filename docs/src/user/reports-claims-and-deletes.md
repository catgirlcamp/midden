# Reports Claims And Deletes

## Reports

When reports are enabled, users can report files and pastes from item pages:

```text
/report/file/{id}
/report/paste/{id}
```

Reports include a reason and optional details. The item has to exist — a report for an unknown ID is rejected. Operators can notify a moderation webhook and an abuse email address.

## Deletes

Delete forms are available at:

```text
/delete/file/{id}
/delete/paste/{id}
```

Authorized account owners can delete their own items when policy allows. Anonymous delete depends on the delete token and the configured delete policy.

## Claims

Claim forms are available at:

```text
/claim/file/{id}
/claim/paste/{id}
```

Claims let an authenticated user attach an anonymous item to their account using the item delete token. This requires `policy.claim_anonymous_item` to allow the signed-in user.

## Unavailable Items

Deleted, quarantined, takedown, and legal hold items render the unavailable item page instead of normal content.
