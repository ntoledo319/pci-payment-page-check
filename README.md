# PCI Payment Page Script Check

Inventory the third-party scripts on your payment page, and fail the build when
one appears that you have not authorized.

[![self-test](https://github.com/ntoledo319/pci-payment-page-check/actions/workflows/selftest.yml/badge.svg)](https://github.com/ntoledo319/pci-payment-page-check/actions/workflows/selftest.yml)

PCI DSS v4.0.1 requirement **6.4.3** asks you to confirm every script loaded on
a payment page is authorized, assure its integrity, and keep an inventory with a
written justification. Requirement **11.6.1** asks you to detect unauthorized
change to those scripts and the security-impacting HTTP headers. Their
future-dated provisions became effective on 31 March 2025 where the respective
requirement applies.

The failure mode is rarely the payment provider's script. It is the analytics
tag added for a campaign, the chat widget added by support, and the tag manager
that lets either happen without a code review. This check runs in CI, so a
script that arrives without review fails a build instead of being discovered
during an assessment.

## Usage

```yaml
- uses: ntoledo319/pci-payment-page-check@v1
  with:
    url: https://yourstore.com/checkout
    allowed-domains: js.stripe.com, www.googletagmanager.com
    fail-on: high
```

Checking a page that is not deployed yet, or sits behind a login:

```yaml
- uses: ntoledo319/pci-payment-page-check@v1
  with:
    html-file: dist/checkout.html
    page-origin: https://yourstore.com/checkout
    allowed-domains: js.stripe.com
```

`html-file` is uploaded to the hosted check. Use a generated public-page
artifact, not an authenticated DOM dump. Never include credentials, card data,
customer data, payment details, or private source.

The first run intentionally leaves `payment-page-scope` unspecified. It returns
the bounded served-HTML inventory and cannot show paid next steps. Review that
inventory, then confirm the payment flow with your acquirer or qualified
reviewer before choosing one of the explicit recipes below for a later run.
Changing scope performs another check; the Action does not guess the scope or
automatically launch a second run.

### After the first inventory, choose the confirmed payment flow

The scope input is not a compliance answer. It prevents the check from turning
an observed script into the wrong product recommendation. Confirm the applicable
questionnaire and responsibilities with your acquirer or qualified reviewer.

**Card fields served by your systems.** Check the page that renders those
fields and list the script hosts your review has authorized:

```yaml
- uses: ntoledo319/pci-payment-page-check@v1
  with:
    url: https://yourstore.com/checkout
    allowed-domains: js.stripe.com, www.googletagmanager.com
    fail-on: high
    payment-page-scope: direct
```

**Processor-owned form or iframe embedded in your page.** The check can
inventory scripts in the merchant page's served HTML. It cannot inspect inside
a cross-origin processor frame, execute JavaScript, or prove the SAQ A
eligibility criterion is satisfied:

```yaml
- uses: ntoledo319/pci-payment-page-check@v1
  with:
    url: https://yourstore.com/checkout
    allowed-domains: js.stripe.com
    fail-on: high
    payment-page-scope: embedded
```

**Redirect or fully outsourced processor page.** Run the check only on a page
you own or are authorized to inspect. The `outsourced` choice keeps the result
from manufacturing direct-page 6.4.3 or 11.6.1 paid next steps:

```yaml
- uses: ntoledo319/pci-payment-page-check@v1
  with:
    url: https://yourstore.com/cart
    fail-on: high
    payment-page-scope: outsourced
```

Do not point the Action at the processor's hosted payment page unless the
processor has explicitly authorized that use.

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `url` | — | Public https URL of the payment page. Use this or `html-file`. |
| `html-file` | — | Workspace-relative UTF-8 HTML to upload and check instead of a URL. Absolute, outside-workspace, and symlink paths are refused. |
| `page-origin` | `https://example.invalid/checkout` | HTTPS page URL used only to resolve relative sources in `html-file` mode. |
| `allowed-domains` | — | Hosts you have authorized, comma-separated. Blank gives an inventory with no authorization check. |
| `fail-on` | `high` | Fail at this severity or above: `high`, `medium`, `low`, `never`. |
| `payment-page-scope` | `unspecified` | `direct`, `embedded`, `outsourced`, or `unspecified`. Only `direct` can expose requirement-specific paid next steps. |
| `api-base` | hosted | Override the service endpoint. |

### Outputs

| Output | Description |
| --- | --- |
| `passed` | `true` when nothing met the `fail-on` threshold |
| `findings` | Number of findings returned |
| `report` | Full JSON result |

A table of findings is written to the job summary on every run.

The summary also links one scope-matched free guide. For a `direct` page, it
renders sample or checkout links only when the hosted result returned those
exact readiness-gated first-party paths. The Action validates their origin and
path, never manufactures an unavailable offer, and never shows a checkout for
`embedded`, `outsourced`, or unspecified scope. Saved-HTML checks can expose the
one-time pack but never the recurring monitor, because a pasted document is not
a schedulable public target.

## What it does and does not do

It reads served HTML (or the saved HTML you explicitly select) and inventories
the script elements present there. It reports observed script hosts outside
your declared list, missing observed integrity attributes, inline blocks, and
bounded parser limitations. `fail-on` evaluates the complete returned finding
set, including medium and low findings.

It does **not** inspect HTTP response headers, fetch referenced script bytes, or
execute the page in a browser. A script injected at runtime by another script
is outside what it can see. It cannot decide whether a script is *authorized* —
only you know that, which is why `allowed-domains` is yours to supply. A clean
result means the bounded checks performed found nothing, not that nothing is
wrong.

It is software-generated evidence for qualified human review. It does not
determine your PCI DSS compliance, does not replace a Qualified Security
Assessor, and does not decide which self-assessment questionnaire applies to
you — your acquiring bank sets that.

## A correction worth knowing

Most write-ups still say SAQ A merchants must comply with 6.4.3 and 11.6.1.
That stopped being true on 31 March 2025: both were removed from SAQ A. PCI SSC
FAQ 1588 says the replacement script-security eligibility criterion applies to
a merchant page with an embedded processor payment form, such as an iframe. It
does **not** apply to processor redirects or fully outsourced payment flows.
For an embedded form, PCI SSC says protective techniques such as those in 6.4.3
and 11.6.1—or confirmation from the compliant processor—can support the
criterion. Confirm the applicable questionnaire with your acquirer or payment
brand.

[PCI SSC FAQ 1588](https://www.pcisecuritystandards.org/faqs/1588/)
· [What changed for SAQ A](https://qi.toledotechnologies.com/pci/saq-a-script-security-confirmation)
· [6.4.3 explained](https://qi.toledotechnologies.com/pci/pci-dss-6-4-3-payment-page-scripts)
· [11.6.1 explained](https://qi.toledotechnologies.com/pci/pci-dss-11-6-1-change-and-tamper-detection)

## Privacy

The action sends the public page URL—or the workspace-relative HTML file you
explicitly select—plus the authorized-domain list and scope choice to the
hosted check. The application processes the request to return the result and
does not persist the raw HTML or free result; ordinary web-server logs still
apply. No account, cookie, or cross-request identifier is created.

The check does not request card numbers, customer names, email addresses,
payment details, credentials, authenticated DOM state, or private source. Do
not include any of them in an uploaded file. Prefer `url` mode when the page is
public; use `html-file` only for a deliberately generated, reviewable artifact.

## From a check to reviewable evidence

The free result is an observation, not a compliance determination. If it finds
an actionable gap, inspect the representative deliverables before deciding
whether to buy:

- [PCI DSS 6.4.3 remediation-pack sample](https://qi.toledotechnologies.com/samples/pci-dss-6-4-3-remediation-pack)
- [PCI DSS 11.6.1 evidence-ledger sample](https://qi.toledotechnologies.com/samples/pci-dss-11-6-1-evidence-ledger)
- [Run the browser check or compare exact prices](https://qi.toledotechnologies.com/pci-4-compliance-scanner)

## Ongoing monitoring

Requirement 11.6.1 asks for evaluation at least every seven days, indefinitely
— a CI run only covers the moment you deploy. A hosted
[evidence ledger](https://qi.toledotechnologies.com/pci/pci-dss-11-6-1-change-and-tamper-detection)
re-checks one authorized public HTTPS page every 72 hours and records each
evaluation in a hash-chained history, so altered or deleted records are
detectable. It provides a private status endpoint for your alerting system to
poll; it does not itself notify personnel.

## Licence

MIT. See `LICENSE`.
