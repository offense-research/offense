# Offense site and tool directory

The site is built from this repository, including canonical tool definitions
and locally generated CLI/SDK distributions. Use Node.js 24+ at the root:

```sh
npm ci
npm run build
npm --prefix site test
npm --prefix site run test:browser
```

The example Worker configuration contains no account, zone or public routes.
Adapt it to your own account and app service before separately authorizing a
deployment. Local source execution is documented in `docs/self-hosting.md`.
The marketing pages describe the operated Offense service; they do not claim
every listed scanner is enabled on a self-hosted installation.

See root THIRD_PARTY_NOTICES.md for Imran Muthuvappa's Apache-2.0 original artwork,
the fonts' separate OFL licenses and trademark reservations.
This release candidate is private pending review; do not publish its assets yet.
