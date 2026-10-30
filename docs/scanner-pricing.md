# Scanner API pricing

The checked-in pilot rates below reduce all scanner base prices and upload surcharges by 50%. Production uses a separately configured `SCAN_TOOL_PRICES_JSON`; editing this rate card does not change live prices. The configured service quote remains authoritative until an explicitly authorized pricing rollout. Existing wallet balances and previously reserved job quotes are unchanged.

Eleven [hosted assessments](hosted-assessments.md) use a flat price per bounded job: Nuclei $0.25, Prowler Cloudflare $0.25, Schemathesis $0.25, ZAP active API $0.50, SSLyze $0.05, Checkov $0.05, TruffleHog verification $0.125, MobSF static $0.50, published OpenSSF Scorecard $0.05, Katana $0.05 and httpx $0.025. There is no additional-MiB fee for these jobs. They remain disabled until their images and required network path are verified and explicitly enabled; see [deployment operations](assessment-operations.md). These are pilot retail prices, not measured cost or margin claims.

## Provisional rate card

Purple charges each selected scanner tool separately. The first 1 MiB of uploaded input is included in its base price. Each additional **started** MiB adds the listed amount. A 1.1 MiB upload therefore uses one additional MiB; a 2.0 MiB upload also uses one. For a job with multiple tools, Purple adds their quoted prices before starting it.

| Scanner tool | First MiB | Each additional started MiB |
| --- | ---: | ---: |
| OpenGrep (`opengrep`) | $0.025 | $0.005 |
| Zizmor GitHub Actions (`zizmor`) | $0.025 | $0.005 |
| OSV dependency intelligence (`osv-scanner`) | $0.025 | $0.005 |
| Semgrep Community Edition (`semgrep`) | $0.025 | $0.005 |
| Pluto Kubernetes deprecations (`k8s-deprecations`) | $0.025 | $0.005 |
| Kubeconform Kubernetes validation (`k8s-manifest-validate`) | $0.025 | $0.005 |
| Trivy dependency vulnerabilities (`trivy-vuln`) | $0.025 | $0.005 |
| Trivy configuration (`trivy-config`) | $0.025 | $0.005 |
| Trivy SBOM (`trivy-sbom`) | $0.025 | $0.005 |
| Gitleaks current files (`gitleaks`) | $0.025 | $0.005 |
| Spectral OpenAPI (`spectral-owasp`) | $0.025 | $0.005 |
| Trivy container image (`trivy-image`) | $0.05 | $0.005 |
| Gitleaks Git history (`gitleaks-history`) | $0.05 | $0.005 |
| GuardDog npm package (`guarddog-npm`) | $0.05 | $0.005 |
| GuardDog PyPI package (`guarddog-pypi`) | $0.05 | $0.005 |
| Cosign signed image (`cosign-image`) | $0.05 | $0.005 |
| ZAP passive HAR (`zap-passive-har`) | $0.125 | $0.025 |

The quoted price for one tool is `base + max(0, ceil(input bytes / 1,048,576) - 1) × additional-MiB price`. For example, a 0.5 MiB OpenGrep job quotes $0.025; a 4.1 MiB image job quotes $0.07; and a 2 MiB passive HAR job quotes $0.15. Uploaded archive size, rather than extracted size, is the billing input. The existing input and daily job limits still apply.

## Prepaid credit and charge rules

Every user receives **$5 in free scanner credit once per immutable GitHub identity**, applied to the workspace where they first claim it, including members of shared workspaces. No payment, installation, contact email or marketing consent is required. Existing users who have never claimed welcome credit receive it on their next authenticated use. Historical $10 grants remain unchanged and do not receive a second grant. Signing in from another device, changing usernames or switching workspaces does not reset the grant. Welcome credit is recorded separately from purchased credit and is not paid revenue.

Customers can add **$10 of scanner credit** through Whop, up to a $50 balance for new loads. Optional automatic top-ups are **off by default**: after an owner explicitly agrees and saves a payment method through Whop, Offense adds $10 when the balance falls below $2, limited to two refill attempts ($20) per rolling 24 hours. Saving the method is a zero-charge setup, not a credit purchase. An unknown payment outcome blocks further automatic charges until reconciled; failed payments, required authentication, refunds and disputes pause automatic top-ups. Owners can turn them off; a payment already submitted may still settle.

Scanner credit is kept separate from Purple's hosted model balance. Purple quotes the maximum charge from the selected tools and actual submitted input, reserves that amount at job creation, and debits it once only if the job and every selected tool complete. Failed or partial jobs release the reservation without a charge. Repeated requests with the same idempotency key and identical input reuse the same job and charge. A workspace can submit at most **10 hosted scans in a rolling 24-hour period**.

Purchased credit is granted only after the server independently confirms a successful, unrefunded payment with Whop; signed webhooks drive durable reconciliation. Refunds and disputes freeze further scanner spending for review. The customer receives the full purchased scanner-credit amount; Whop's processing fee is a Purple operating cost. [Whop's published domestic card rate](https://whop.com/network/pricing/) is 2.7% plus $0.30 per successful transaction, or $0.57 on a $10 load before optional fees. International cards, currency conversion, and enabled Whop services can add fees. See [billing operations](scanner-billing-operations.md) for consent, webhook subscriptions and reconciliation.

## Why these are pilot prices

This rate card is a **pricing decision**, not a claim that each scan costs Purple its listed price. Purple's scanner currently uses a `standard-2` Cloudflare container: 1 vCPU, 6 GiB memory, and 12 GB disk. At Cloudflare's published marginal rates, full CPU use plus provisioned memory and disk is about **$0.00003584 per running second**, before Workers, Durable Objects, R2, and startup time. [Cloudflare Containers pricing](https://developers.cloudflare.com/containers/platform/pricing/) and [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) describe those charges. [R2 pricing](https://developers.cloudflare.com/r2/pricing/) adds storage and operations; standard storage is $0.015 per GB-month, a write is $4.50 per million, a read is $0.36 per million, and deletion is free.

The [production synthetic canaries](e2e/hosted-scans-next-production.json) took about 0.8–4.8 seconds of tool time for the non-ZAP additions and 133 seconds for ZAP. Tool time excludes container startup and cleanup, so it does not establish the full cost of a customer job. The pilot prices allow for that overhead, failed jobs that are not charged, payment fees, and scanner maintenance. Review the rates against Cloudflare's billed usage and real customer job sizes before raising the daily quota.

Local `source-scan.mjs` and sandbox `api-test.mjs` do not call the hosted metering API and have no Purple scanner charge. Local tool and container resources remain under the developer’s control. Zizmor’s hosted price is a pilot rate requiring the same explicit quote and complete-run settlement as the other source tools.
