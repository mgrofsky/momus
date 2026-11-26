# Responsible use

Use Momus only on systems you own. The tool is built for that one case: before a domain is scanned, an administrator must state "I own this domain and the systems it points to." Do not use it on systems you do not own, even with their owner's permission; scanning a system without permission can break the law where you are and where the system is, and it can break the system.

## Who may use it, and on what

- The person who runs Momus must own every domain they add to the scope, and the systems those domains point to. The brain asks an administrator to confirm exactly this ("I own this domain and the systems it points to.") before a domain is added, and records who confirmed it and when.
- A domain is scanned only after the scanner finds a DNS record that only your install can produce. This proves that someone controls the domain's DNS. It does not prove that you own every system a name points to: a name under your domain can point to a hosting provider, a software-as-a-service vendor, or an address that has changed hands. Read the asset inventory before you approve active checks, and know that the inventory itself already sends requests to every host it finds (below).
- **DNS verification is a due-care control. Anyone with the source can remove it. It does not make scanning someone else's systems permitted.** The same is true of every other control in [scope and authorization](scope-and-authorization.md).

## What a scan does to a target

Even the default settings send real traffic: DNS questions, HTTP requests to every live host, TLS handshakes, port scans of approved addresses, and the templates of the nuclei scanner.

The inventory, which runs before any approval, is not passive. It sends DNS questions to the domain's nameservers (including a zone-transfer attempt), and HTTP and HTTPS requests with a TLS handshake, plus the whatweb and wafw00f fingerprinting requests, to every host it discovers whose addresses pass the address gate. It sends no port scan, no TLS scan, and no nuclei templates. A name discovered under your domain may point at a system you do not own, and these requests reach that system before you have reviewed the list. Exclude names you know are hosted by others before the first inventory. A fragile service can slow down or fail under that load. The default rate profile (`low`) is the gentlest; `normal` and `fast` send more requests at once.

The `active` check profile is off by default. Turning it on (the Scope page, "Turn aggressive checks on") adds nuclei templates tagged `default-login`, `sqli`, `rce`, `lfi`, `ssrf`, `xss`, and `injection`. These templates send requests built to trigger the flaw they test for. On a vulnerable system they can:

- sign in with default credentials and create a session;
- send input that a vulnerable application passes to its database, its file system, its template engine, or a shell;
- make the target fetch an address of the template's choosing;
- leave entries in logs and alerts in monitoring, and write data if the flaw allows it.

Templates tagged `dos`, `fuzz`, `fuzzing`, `intrusive`, `bruteforce`, or `brute-force` never run, in either profile (`scanner/config/exclude_tags.txt`). Out-of-band callbacks to third-party servers are off. Turn `active` on only for systems where you accept these effects, ideally after telling the people who run them.

## Before scanning in a hosted environment

Cloud and hosting providers have their own rules about security testing of the systems they host, including systems you rent from them. Some allow it without notice, some ask for notice, and some forbid certain kinds of tests. Read your provider's current policy before the first scan, and again before you turn on `active`.

Content delivery networks, web application firewalls, and software-as-a-service vendors that serve names under your domain are not your systems. Momus recognizes such hosts by their CNAME and classes them as CDN-fronted or third party, which means no port scan, and for third-party hosts a smaller set of templates (see [scope and authorization](scope-and-authorization.md#9-host-classes-and-what-each-receives)). It still sends them HTTP requests, TLS scans, and templates. The recognition has limits:

- An address in your owned ranges, or a host in your approved-hosts list, takes precedence over a provider CNAME: such a host is classed as owned and gets the full set of checks, including a port scan.
- The provider address-range list (`scanner/config/third_party_ranges.txt`) ships empty, so a provider host reached by a plain address record, with no CNAME, is not recognized by its address (only a CDN or WAF edge that the HTTP probe reports is).
- A provider host whose CNAME is not on the shipped lists is classed `unverified`. After approval it gets the same web checks as an owned host (TLS scan and the generic, technology, DNS, and fingerprint template passes), never a port scan.

If a provider's terms forbid this traffic, exclude those names from the scope.

Tell the people who watch your systems before a first scan, so that alerts are not mistaken for an attack. The scanner's version watch identifies itself with the user agent `momus-version-watch`.

## Responsibility

Momus is provided as it is, without any promise that it is fit for a purpose or free of faults. The people who wrote it accept no responsibility for how it is used, and no responsibility for harm caused by scanning systems the person running it does not own. You are responsible for what you scan, for owning it, and for what your scans do. The license states the terms that apply: the [MIT License](../LICENSE).
