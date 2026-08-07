# Files

The home page is the primary file upload surface.

## Upload

The upload form accepts:

- `file`: the file bytes.
- `expires`: optional expiry duration.
- `visibility`: `unlisted`, `private`, or `public` when public browse is enabled.

Anonymous uploads are allowed by default. If policy requires authentication, sign in first.

## Results

A successful upload returns:

- A page URL.
- A raw file URL.
- A delete token for anonymous uploads when the delete policy supports it.

Keep delete tokens private. They can delete or claim anonymous items depending on policy.

## Visibility

- `unlisted`: reachable by direct link.
- `private`: visible only to the owning account and moderators.
- `public`: visible in `/browse` when public browse is enabled.

## Browsing

`/browse` lists public files and public pastes newest first, `discovery.page_size` of each per page, capped at 100 per listing.

The two listings page independently, so "Older items" carries a cursor for each: `before_file` and `before_paste`. Follow the link rather than constructing these by hand. A cursor is `<created_at>.<public_id>`; the ID is part of it so that items uploaded within the same second still page correctly.

These replaced a single `before` parameter. A stale link using it is ignored and lands on the first page.

## Preview Pages

When `features.preview_pages = true`, file links open a preview page first. Otherwise, file links serve the raw file directly.

A preview page is part of the application, so it is always served from the application origin even when files have their own domain. The bytes it links and embeds come from the file domain.

## URL Upload

When `features.upload_by_url = true`, `/url-upload` lets users fetch a remote `http` or `https` URL into Midden. Operators can restrict hosts, ports, redirects, response size, and private IP access.
