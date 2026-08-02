# Readiness

A release is judge-ready only when all of the following receipts exist for one
merged master SHA:

- green CI, workflow-security, CodeQL and supply-chain runs;
- attested SPA and Lambda candidates;
- attested DataHub Cloud image release at an immutable digest;
- attested DataHub Core AMI v2 receipt;
- successful staging deployment observation;
- successful production promotion bound to that staging receipt;
- current availability and production-posture receipts;
- successful CloudWatch -> KMS SNS -> KMS SQS alarm-delivery proof;
- live four-component DataHub evidence for the canonical synthetic dataset;
- judge user/access verification and submission artifacts.

Source implementation does not imply that AWS, DNS, the Cloud trial or Devpost
submission is complete. External configuration remains open until its exact
receipt is present. The Cloud trial is an enhancement, not a single point of
failure: the zero-idle OSS Core profile remains the reproducible fallback
through judging.

Video, post and Devpost submission are deliberately last-mile tasks after the
technical receipts close.
