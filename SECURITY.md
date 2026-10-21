# Security policy

## Reporting a vulnerability

Two equal routes, with the same response times below:

- Email **kevin.borger@gjk-partners.nl**.
- GitHub private vulnerability reporting: the "Report a vulnerability" button
  on the Security tab. That button only works while this repository is public
  and private reporting is switched on for it; if you do not see it, use the
  email address - that route is always open.

Please do not open a public issue before a fix exists.

What helps: the version or commit you tested, what you did, what you observed,
and what you expected. A proof of concept is welcome but not required.

## What to expect

| step | timing |
|---|---|
| first substantive response (valid / not valid / need more information) | within 5 working days |
| fix or a dated plan | within 90 days of your report |
| public disclosure | after the fix ships, or 90 days after your report - whichever comes first, coordinated with you |

If a report needs longer than 90 days, we say so and why, before the window
ends. Silence is never the answer.

## Supported versions

| version | supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no - these were internal pre-release builds |

## Safe harbor

We will not pursue or support legal action against anyone who reports a
vulnerability in good faith and who:

- stays within their own systems and their own test appliance;
- does not access, modify or exfiltrate data belonging to anyone else;
- does not degrade a service other people depend on;
- gives us a reasonable window to fix the issue before disclosing it.

Report first, publish later, and we will treat you as a colleague.

## Scope

**In scope** - a finding here is a vulnerability in this product:

- an answer that states a verdict on a source that could not be read;
- any path along which the confirmation code reaches the language model;
- any path along which a reading tool opens a socket;
- a real object name that reaches an answer at disclosure level `beperkt` or
  `minimaal`;
- code execution that does not follow from the configuration file or from one
  of the two configured PowerShell scripts.

**Out of scope** - these are your environment, not this product:

- the operating system, accounts and permissions of the machine that runs the
  server;
- the MCP host and the AI client that calls it, and what that client does with
  an answer;
- the collector script and the write script themselves, and the appliance they
  reach;
- your outbound network policy;
- the cloud AI vendor as a recipient of whatever ends up in the chat.

Three trust boundaries an operator has to protect, because this product
cannot:

- **the export map** - whoever can write it can supply an export, but not
  record that this server collected it: a target-bound answer and every
  writing tool that uses the export need the server's own provenance record,
  kept outside the export map (the ledger map, or a `herkomst` directory next
  to the configuration file; the server does not start when either map lies
  inside the other). Protect those directories like the configuration file;
- **the knowledge path** - whoever can write it can change the knowledge. With
  `kennispin` in the configuration a changed package is refused; without it
  every floor and CVE verdict, and the extra step after the upgrade, is
  reported as not established;
- **the sso presenter** (`handelen.codekanaal.pad`) - operator-supplied code
  that receives the confirmation code. It is trusted to speak the one-line
  protocol and mirror the section and fingerprint, not checked for what it
  shows.

The full trust model, including which inputs this product trusts and why, is in
the Dutch customer statement:
**[docs/klant/SECURITY.md](docs/klant/SECURITY.md)**. The customer-facing
data-flow statement lives in
[docs/klant/BEVEILIGING-EN-DATASTROMEN.md](docs/klant/BEVEILIGING-EN-DATASTROMEN.md).
