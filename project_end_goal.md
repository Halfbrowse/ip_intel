ATTRIBUTOR

We propose an automated systems will take every channel/domain/Ip address that our detection teams find during their investigations and run them through a scanner. Keeping the results in a database so that we ca build up a larger picture of who controls what. By doing this we aim to uncovering hidden attribution links and to move up the chain to the companies and individuals behind these channels and domains. This will allow us two things, firstly to gain a better understanding of the networks we are tracking and secondly to give our responses better accuracy. 
We aim for the system to be usable as follows, ingesting data form OpenCTI, in the form of domains and non-social media channels, as well as allowing users to enter a domain/list of domains, to check against the data we have. 
DESIGN PRINCIPLES
The system should be modular and aysnc, it should be capable of handling large amounts of data streaming through it and multiple users being active on it at the same time. It should make use of our internal VPN solution to bypass API limits. It should expose an internal API so its data can be consumed by either custom tools or 3rd party tools. Its frontend should be designed in such a way as to focus on the connections a channel/group of channels have to either each other or to the database at large. 
SOURCES (FREE)

Provider	What it gives us
DNS	A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, PTR records
WHOIS	Registrar, creation/expiry dates, nameservers, org, country
IP WHOIS / RDAP	ASN, ASN name, country, CIDR, network name
crt.sh	Subdomains, cert history, issuers, cross-domain SANs – NEED TO GET ALT
CIRCL Passive DNS	Historical A/AAAA records with first-seen/last-seen timestamps
HackerTarget	Co-hosted domains on the same IP; subdomain→IP mappings
urlscan.io	Historical IPs serving the domain; analytics/tracking IDs
Direct TLS probes	Live cert CN, SANs, issuer, serial, fingerprint per IP
SSH host keys	SSH fingerprints from non-Cloudflare IPs
Page metadata	Analytics IDs (GA/GTM/FB/TikTok/Yandex), HTML lang, CMS, social handles, favicon hash
Email security	SPF, DKIM (keys + provider attribution), DMARC, MTA-STS, BIMI
Well-known files	ads.txt, security.txt, assetlinks.json, apple-app-site-association, openid-configuration, humans.txt
Mail client config	Autodiscover/autoconfig XML

TECHNICAL REQUIREMENTS
The app will be built using python, uv and dockerized to be hosted on a server. It will use the docker compose plugin to communicate with other services (VPN solution). It will use PostgreSQL as its DB and it will have Mattermost and email alerts built in. For the frontend it will use react, this is to ensure we can modify all aspects of it. The frontend will need to be smooth and available in light and dark mode, it will need to be focused on how two or more domains are linked nad the percent confidence rating we are of the ultimate question, are these domains controlled by the same entity? 
For the DB, it will obviously inform the app, but it will also be designed so that we can do further analysis on the data. To make better insights further down the line, to ensure this we should use Foreign key links on a per table basis to ensure that each domain has its attributes correctly linked.	
