# Shopify's Bug Bounty Program

We reward security researchers for finding and reporting vulnerabilities that help keep our platform secure. Our bug bounty program offers rewards up to $200,000 and bonuses for outstanding contributions.

Here’s what you can expect:
- Quick review and triage of reports with high-quality evaluations.
- Full transparency on report decisions, including adding you to duplicate reports on HackerOne.
- Prompt bounty awards after triage, except in rare cases.

We value all contributions, from minor issues to critical vulnerabilities, as they help enhance Shopify’s security.

## Early Access Program

A special invite-only program where select researchers get early access to Shopify features before they're widely released. This exclusive opportunity lets you discover vulnerabilities in our newest innovations while earning bounties.

Criteria for invitation:

- Submitted 4 or more reports over the past 2 years.
- 50% or higher rate of success on those reports

Please note, invitations are extended at Shopify's discretion based on quality contributions to our security ecosystem.


## Getting started
1. Review and understand the [participation rules](https://bugbounty.shopify.com/criteria?q=rules), the list of [assets in scope](https://bugbounty.shopify.com/criteria?q=scope), and the list of [ineligible issues](https://bugbounty.shopify.com/criteria?q=ineligible-issues).
1. Familiarize yourself with the `@wearehackerone.com` email address which must be used when creating a Shopify account. This alias is provided by HackerOne and you can learn more about it in their [documentation](https://docs.hackerone.com/en/articles/8404308-hacker-email-alias).
1. Create a Shopify account using [this link](https://partners.shopify.com/signup/bugbounty) and follow the registration process.
1. You must test only against stores you have created. Testing against live merchants is prohibited and can result in reports being closed as `Not Applicable` and/or your disqualification from the Shopify bug bounty program.
1. Consult [Shopify Help Center](https://help.shopify.com/) for further information on how to build a store and to discover platform features. For newest product updates, keep an eye on our [Core Change Log](https://changelog.shopify.com/) and [Partners Blog](https://www.shopify.ca/partners/blog/topics/shopify-news).

If you need further clarification of the rules or scope of our bug bounty program, please don't hesitate to contact us at bugbounty@shopify.com.

## Eligibility
The scope of the bug bounty program is limited to the assets listed on the scope page for this program. Valid vulnerabilities on any asset not explicitly listed in scope may be accepted but are ineligible for a reward. As a general rule:
- Reports which do not demonstrate relevant security impact to Shopify or our Merchants by providing a functional proof of concept will be closed as N/A.
- We reward researchers based on the scenario that yields the highest overall severity score , provided that the scenario is plausible and directly linked to the root issue. In cases where multiple reports share the same root cause, these will be closed as Duplicate.
- We will only award and triage reports when the root cause is under our control.
- IDOR eligibility will be evaluated considering the identifier predictability, the data accessed and overall impact on the service.
- Reports of a vulnerability disclosing sensitive PII will be evaluated on a case by case basis, considering the overall impact on Shopify's merchant data.

## Typical Bounty Amounts
Bounty amounts will be determined using [Shopify's Bug Bounty Calculator](https://bugbounty.shopify.com/calculator). In most cases, we will only triage and reward vulnerabilities with a score greater than 0. A score under 3 will result in a $500 bounty. Scores greater than or equal to 3 will be determined by the calculator. In rare cases, we may choose to accept and award a bonus for an issue with a score of  0 when we see a high potential for future security impact and make a change as a result of the report. Bonuses are determined as a percentage (10% of what the bounty is estimated at for an exploitable issue), with a minimum of $500 and a maximum of $5,000.

While our bounty table states the minimum bounty per severity, scores for non-core properties listed in scope will be determined with Environment Score modifiers set to Low for Confidentiality, Integrity, and Availability Requirements. In addition to the score, the bounty is lowered if it is determined that the reported issue is not scalable to impact most or all Shopify as indicated in our calculator.

## Leaked Credentials
In alignment with HackerOne’s guidance and terms, Shopify accepts reports of leaked credentials, including Authentication material for Shopify APIs and/or Shopify infrastructure. Hackers should submit the leaked credentials to the program and should not test their validity beyond authenticating and then immediately deauthenticating - without exercising any functionality. Likewise, Hackers should not share these credentials beyond their report to the program.

## Rules for participation
The following rules must be followed in order for any rewards to be paid:
- **Eligibility for Rewards**
  - Only test against stores you created using your HackerOne `YOURHANDLE @ wearehackerone.com` registered email.
  - Do not attempt to gain access to, or interact with stores you didn’t create.
  - Follow all reporting rules.
  - Do not disclose issues publicly before resolution or without permission.
- **Program Modifications**
  - Shopify reserves the right to modify rules or invalidate submissions at any time.
  - Shopify may cancel the bug bounty program without notice at any time.
- **Contact Restrictions**
  - Do not contact Shopify Support as part of your testing or to ask about the bounty program, to pre-validate reports nor to ask for updates. Violating this will disqualify you from receiving a reward and may result in a program ban.
- **Employment Status**
  - You are not an employee of Shopify
  - Shopify employees must report bugs to the internal bug bounty program.
- **Vulnerability Reporting**
  - You must report any discovered vulnerability to Shopify as soon as you have validated the vulnerability.

Failure to follow any of the foregoing rules will disqualify you from participating in this program.
- **General Rules**
  - Reports must demonstrate relevant CVSS impact to Shopify, Shop users, our partners or our merchants with a functional proof of concept. Reports without this will be closed as N/A.
  - Rewards are based on the highest CVSS score scenario that is plausible and linked to the root issue. Multiple reports with the same root cause will be closed as Duplicate.
  - You hereby represent, warrant and covenant that any content you submit to Shopify is an original work of authorship and that you are legally entitled to grant the rights and privileges conveyed by these terms. You further represent, warrant and covenant that the consent of no other person or entity is or will be necessary for Shopify to use the submitted content.
  - By submitting content to Shopify, you irrevocably waive all moral rights which you may have in the content.
  - All content submitted by you to Shopify under this program is licensed under the MIT License.
- **Notes**
  - This program is not open to individuals who are on sanctions lists, or who are in countries on sanctions lists.
  - You are responsible for any tax implications resulting from payouts depending on your country of residency and citizenship.
  - Shopify reserves the right to cancel this program at any time and the decision to pay a bounty is entirely at our discretion. Your testing and submission must not violate any law, or disrupt or compromise any data that is not your own.
  - There may be additional restrictions on your ability to submit content or receive a bounty depending on your local laws.
