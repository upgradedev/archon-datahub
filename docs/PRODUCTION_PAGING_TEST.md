# Production alarm-delivery proof

The alarm route is deliberately AWS-native and independently testable:

`CloudWatch alarm -> customer-KMS SNS topic -> customer-KMS SQS proof queue`.

`production-paging-test.yml` runs through the protected
`production-paging-test` environment and a dedicated OIDC role. It reads the
exact Judge stack outputs, validates queue encryption/retention and the
topic-bound queue policy, primes the control-plane alarm to OK, drains stale
messages, and forces a unique ALARM transition.

The subscription uses raw delivery. The workflow accepts only a message whose
alarm name, ALARM state and unique state reason all match this run. It deletes
every received message, retains only the matched body digest, and registers an
EXIT trap that restores OK and drains the proof queue even after failure.

The sanitized `archon.production-alarm-delivery/v2` receipt is attested and
retained for 90 days. No email address, webhook, second reviewer, raw ARN,
account identifier or credential is retained. External notification channels
can subscribe later, but they are not required to prove the application alarm
path.
