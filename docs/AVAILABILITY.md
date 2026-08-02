# Availability evidence

`availability.yml` runs every 30 minutes and can also be dispatched manually.
It is bound to the current reviewed master head and enters the protected
`production-observer` environment only after the GitHub control-plane gates
succeed.

The probe verifies the live three-stack AWS controls, requires Core desired
capacity zero, requests the canonical CloudFront SPA and
`/api/runtime-profiles` over TLS, validates security headers and requires
exactly the Cloud and Core capability projections with a valid automatic
selection. It retains only response digests and sanitized status fields.

The resulting `archon.production-availability/v2` receipt and lean-runtime
observation are attested and retained for 90 days. Credentials, endpoints,
account identifiers and raw DataHub payloads are not retained.
