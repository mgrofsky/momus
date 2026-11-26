#!/usr/bin/env python3
"""fingerprint.py - turn one host's raw fingerprint evidence into categorized technology components.

Pure functions, stdlib only. ingest.py builds the evidence bundle per host from the files the scan
already produces (httpx, whatweb, wafw00f, nuclei, nmap, sslscan, DNS) and calls:

  normalize(ev)              -> [component]   {category, name, version, source, evidence}
  hosting(ev)                -> (label, source) | (None, None)
  profile(components, ev)    -> one row per host (os, web_server, language, framework, cms, cdn, waf, hosting, tls...)
  eol_status(name, version, eol_data, on_date) -> (eol 0/1/None, eol_date)
  eol_cycle / EOL_PRODUCTS   -> which endoflife.date products are tracked (config/eol_products.txt must list the same slugs)

Nothing here probes a host or opens a network connection. The evidence is only what the scan tools observed;
the ASN (Team Cymru) and end-of-life (endoflife.date) lookups run earlier, in the enrich step (enrich.py).
"""
import datetime as dt, ipaddress, os, re

CATEGORIES = ("os", "web_server", "language", "framework", "cms", "js_library", "cdn", "waf", "load_balancer",
              "hosting", "service", "tls", "analytics", "other")

# Canonical name -> category. Seeded from what the scans actually return (httpx tech-detect names, whatweb
# plugin names, Server / X-Powered-By headers). Unknown names land in "other" rather than being dropped.
CATALOG = {
    # operating systems (banners and headers only; nothing active)
    "Unix": "os", "Linux": "os", "Debian": "os", "Ubuntu": "os", "CentOS": "os", "Red Hat": "os", "Fedora": "os",
    "Amazon Linux": "os", "Windows": "os", "Windows Server": "os", "FreeBSD": "os", "OpenBSD": "os", "Alpine": "os",
    "SUSE": "os", "Oracle Linux": "os", "Rocky Linux": "os", "AlmaLinux": "os", "Raspbian": "os", "macOS": "os",
    # web servers / application servers
    "Apache": "web_server", "nginx": "web_server", "IIS": "web_server", "LiteSpeed": "web_server", "OpenResty": "web_server",
    "Caddy": "web_server", "Tomcat": "web_server", "Jetty": "web_server", "Microsoft-HTTPAPI": "web_server", "lighttpd": "web_server",
    "uvicorn": "web_server", "Gunicorn": "web_server", "uWSGI": "web_server", "Werkzeug": "web_server", "Kestrel": "web_server",
    "Phusion Passenger": "web_server", "Puma": "web_server", "Unicorn": "web_server", "Tornado": "web_server", "Hypercorn": "web_server",
    "Daphne": "web_server", "WildFly": "web_server", "JBoss": "web_server", "WebLogic": "web_server", "WebSphere": "web_server",
    "GlassFish": "web_server", "GSE": "web_server", "Google Frontend": "web_server", "UploadServer": "web_server",
    "Cowboy": "web_server", "Mongrel": "web_server", "WEBrick": "web_server", "Thin": "web_server", "Node.js": "language",
    # languages / runtimes
    "PHP": "language", "Python": "language", "Ruby": "language", "Java": "language", "Go": "language", "Perl": "language",
    ".NET": "language", "ASP.NET": "language", "Erlang": "language", "Elixir": "language", "Lua": "language", "Scala": "language",
    "ColdFusion": "language", "Kotlin": "language",
    # frameworks
    "Express": "framework", "Django": "framework", "Flask": "framework", "FastAPI": "framework", "Ruby on Rails": "framework",
    "Laravel": "framework", "Symfony": "framework", "CodeIgniter": "framework", "CakePHP": "framework", "Yii": "framework",
    "Zend": "framework", "Kohana": "framework", "Spring": "framework", "Struts": "framework", "Play": "framework",
    "Phoenix": "framework", "Next.js": "framework", "Nuxt.js": "framework", "Gatsby": "framework", "Blazor": "framework",
    "Angular": "framework", "AngularJS": "framework", "React": "framework", "Vue.js": "framework", "Ember.js": "framework",
    "Svelte": "framework", "Backbone.js": "framework", "Meteor": "framework", "NestJS": "framework", "Koa": "framework",
    "Hapi": "framework", "Sails.js": "framework", "Slim": "framework", "Lumen": "framework", "Bottle": "framework",
    "Pyramid": "framework", "Sinatra": "framework", "Grails": "framework", "Vaadin": "framework", "JSF": "framework",
    "Docusaurus": "framework", "Hugo": "framework", "Jekyll": "framework",
    # CMS / applications
    "WordPress": "cms", "Drupal": "cms", "Joomla": "cms", "Magento": "cms", "WooCommerce": "cms", "Ghost": "cms",
    "TYPO3": "cms", "Concrete CMS": "cms", "Umbraco": "cms", "Sitecore": "cms", "Craft CMS": "cms", "Contentful": "cms",
    "MediaWiki": "cms", "DokuWiki": "cms", "Moodle": "cms", "Confluence": "cms", "Jira": "cms", "Bitbucket": "cms",
    "GitLab": "cms", "Gitea": "cms", "Nextcloud": "cms", "ownCloud": "cms", "phpMyAdmin": "cms", "Zabbix": "cms",
    "Grafana": "cms", "Kibana": "cms", "Jenkins": "cms", "n8n": "cms", "Nagios": "cms", "Cacti": "cms", "Portainer": "cms",
    "SonarQube": "cms", "Swagger UI": "cms", "Roundcube": "cms", "Zimbra": "cms", "Outlook Web App": "cms",
    "Microsoft Exchange": "cms", "FusionPBX": "cms", "FreePBX": "cms", "Asterisk": "cms", "FreeSWITCH": "cms",
    "Ceph-Dashboard": "cms", "cPanel": "cms", "Plesk": "cms", "Webmin": "cms", "HubSpot": "cms",
    "Webflow": "cms", "Wix": "cms", "Squarespace": "cms", "Shopify": "cms", "Salesforce": "cms", "Marketo": "cms",
    "Unbounce": "cms", "Instapage": "cms", "Zendesk": "cms", "Intercom": "cms", "Okta": "cms", "Atlassian Statuspage": "cms",
    "ReadMe": "cms", "GitBook": "cms", "Firebase": "cms", "Google Search Appliance": "cms", "Odoo": "cms", "SugarCRM": "cms",
    "SuiteCRM": "cms", "Mautic": "cms", "Matomo": "cms", "osTicket": "cms", "MantisBT": "cms", "Redmine": "cms",
    # JavaScript / front-end libraries
    "jQuery": "js_library", "jQuery UI": "js_library", "jQuery Migrate": "js_library", "Bootstrap": "js_library",
    "Modernizr": "js_library", "Lodash": "js_library", "Underscore.js": "js_library", "Moment.js": "js_library",
    "Font Awesome": "js_library", "Handlebars": "js_library", "Prototype": "js_library", "YUI": "js_library",
    "MooTools": "js_library", "Dojo": "js_library", "Ext JS": "js_library", "Select2": "js_library", "Slick": "js_library",
    "Swiper": "js_library", "Lightbox": "js_library", "Chart.js": "js_library", "D3": "js_library", "Highcharts": "js_library",
    "core-js": "js_library", "Polyfill": "js_library", "webpack": "js_library", "Vite": "js_library", "RequireJS": "js_library",
    "Popper": "js_library", "Animate.css": "js_library", "Tailwind CSS": "js_library", "Materialize CSS": "js_library",
    "Foundation": "js_library", "Semantic UI": "js_library", "Bulma": "js_library", "Google Font API": "js_library",
    "Material Design Lite": "js_library", "Vuetify": "js_library", "Element UI": "js_library", "Ant Design": "js_library",
    "MUI": "js_library", "Emotion": "js_library", "styled-components": "js_library", "Socket.io": "js_library",
    "Axios": "js_library", "Hammer.js": "js_library", "GSAP": "js_library", "Three.js": "js_library", "Sentry": "js_library",
    "TinyMCE": "js_library", "CKEditor": "js_library", "DataTables": "js_library", "Owl Carousel": "js_library",
    "FancyBox": "js_library", "Isotope": "js_library", "WOW": "js_library", "Google Maps": "js_library", "YouTube": "js_library",
    "Vimeo": "js_library", "reCAPTCHA": "js_library", "hCaptcha": "js_library", "Stripe": "js_library", "PayPal": "js_library",
    # CDN / edge
    "CloudFront": "cdn", "Cloudflare": "cdn", "Akamai": "cdn", "Fastly": "cdn", "Azure CDN": "cdn", "Google Cloud CDN": "cdn",
    "Imperva": "waf", "Incapsula": "waf", "Sucuri": "waf", "AWS WAF": "waf", "Cloudflare WAF": "waf", "Google Cloud Armor": "waf",
    "Azure Front Door": "cdn", "Fortinet": "waf", "FortiGate": "waf", "F5 BIG-IP": "waf", "Barracuda": "waf",
    "StackPath": "cdn", "KeyCDN": "cdn", "BunnyCDN": "cdn", "jsDelivr": "cdn", "cdnjs": "cdn", "unpkg": "cdn",
    # load balancers / proxies
    "Amazon ELB": "load_balancer", "awselb": "load_balancer", "HAProxy": "load_balancer", "Envoy": "load_balancer",
    "Traefik": "load_balancer", "Kong": "load_balancer", "Tyk": "load_balancer", "Varnish": "load_balancer",
    "Squid": "load_balancer", "Istio": "load_balancer", "Zuul": "load_balancer", "Apigee": "load_balancer",
    "Google Cloud Load Balancing": "load_balancer", "Azure Application Gateway": "load_balancer", "Pound": "load_balancer",
    # hosting / cloud
    "Amazon Web Services": "hosting", "Amazon S3": "hosting", "Google Cloud": "hosting", "Microsoft Azure": "hosting",
    "Vercel": "hosting", "Netlify": "hosting", "Heroku": "hosting", "Fly.io": "hosting", "GitHub Pages": "hosting",
    "DigitalOcean": "hosting", "Linode": "hosting", "Render": "hosting", "Railway": "hosting", "OVH": "hosting",
    "Hetzner": "hosting", "Rackspace": "hosting", "Amazon EC2": "hosting", "Amazon API Gateway": "hosting",
    "Azure App Service": "hosting", "Google App Engine": "hosting", "Firebase Hosting": "hosting", "WP Engine": "hosting",
    "Pantheon": "hosting", "Kinsta": "hosting", "SendGrid": "hosting", "Mailgun": "hosting", "Mailchimp": "hosting",
    # services / components
    "OpenSSL": "service", "mod_ssl": "service", "mod_perl": "service", "mod_python": "service", "mod_wsgi": "service",
    "mod_jk": "service", "mod_fcgid": "service", "mod_auth_kerb": "service", "mod_pagespeed": "service", "OpenSSH": "service",
    "Postfix": "service", "Exim": "service", "Sendmail": "service", "Dovecot": "service", "MySQL": "service",
    "MariaDB": "service", "PostgreSQL": "service", "MongoDB": "service", "Redis": "service", "Memcached": "service",
    "Elasticsearch": "service", "OpenSearch": "service", "RabbitMQ": "service", "Kafka": "service", "MinIO": "service",
    "Docker": "service", "Kubernetes": "service", "Ceph": "service", "BIND": "service", "PowerDNS": "service",
    "ProFTPD": "service", "vsftpd": "service", "Pure-FTPd": "service", "Samba": "service", "Microsoft SQL Server": "service",
    "Oracle Database": "service", "Keycloak": "service", "Auth0": "service", "OpenID": "service", "SAML": "service",
    "Let's Encrypt": "service", "DigiCert": "service", "HTTP/2": "service", "HTTP/3": "service", "SPDY": "service",
    "WebSocket": "service", "PWA": "service", "SMPP": "service", "SIP": "service", "RTP": "service",
    # analytics / marketing tags
    "Google Analytics": "analytics", "Google Tag Manager": "analytics", "Hotjar": "analytics", "Segment": "analytics",
    "Mixpanel": "analytics", "New Relic": "analytics", "Datadog": "analytics", "Facebook Pixel": "analytics",
    "LinkedIn Insight Tag": "analytics", "HubSpot Analytics": "analytics", "Pardot": "analytics", "Marketo Munchkin": "analytics",
    "Microsoft Clarity": "analytics", "Amplitude": "analytics", "FullStory": "analytics", "Heap": "analytics",
    "Pendo": "analytics", "Drift": "analytics", "Twitter Ads": "analytics", "Google Ads": "analytics",
    "Open Graph": "other", "Twitter Cards": "other",
    "Google Hosted Libraries": "cdn", "BootstrapCDN": "cdn", "AtlassianEdge": "cdn", "Cloudflare Bot Management": "waf",
    "Moment Timezone": "js_library", "NVD3": "js_library", "ZURB Foundation": "js_library", "Onsen UI": "js_library",
    "bowser": "js_library", "phpBB": "cms", "Google Cloud Storage": "hosting", "Google Cloud Trace": "analytics",
    "LinkedIn Ads": "analytics", "Twilio": "hosting", "Zoom": "hosting", "DocuSign": "hosting", "Freshdesk": "cms",
    "Atlassian": "hosting", "Help Scout": "cms", "Greenhouse": "cms", "Lever": "cms", "Workable": "cms", "BambooHR": "cms",
    "Microsoft 365": "hosting", "Webex": "hosting", "RingCentral": "hosting", "Customer.io": "analytics", "GitHub": "hosting",
    "Vultr": "hosting", "Oracle Cloud": "hosting", "IBM Cloud": "hosting", "Leaseweb": "hosting", "GoDaddy": "hosting",
}

# Lower-cased aliases -> canonical catalog name. httpx (Wappalyzer), whatweb and headers all spell things
# differently.
ALIASES = {
    "apache http server": "Apache", "apache httpd": "Apache", "apache2": "Apache", "httpd": "Apache",
    "microsoft-iis": "IIS", "microsoft iis": "IIS", "iis": "IIS", "nginx": "nginx", "openresty": "OpenResty",
    "apache tomcat": "Tomcat", "tomcat": "Tomcat", "apache-coyote": "Tomcat", "coyote": "Tomcat", "jetty": "Jetty",
    "litespeed": "LiteSpeed", "microsoft-httpapi": "Microsoft-HTTPAPI", "microsoft httpapi": "Microsoft-HTTPAPI",
    "google frontend": "Google Frontend", "gfe": "Google Frontend", "gse": "GSE", "gws": "Google Frontend",
    "ghs": "Google Frontend", "opengse": "GSE", "linkedin ads": "LinkedIn Ads", "moment timezone": "Moment Timezone",
    "amazon-cloudfront": "CloudFront", "amazon cloudfront": "CloudFront", "cloudfront": "CloudFront",
    "cloudflare": "Cloudflare", "cloudflare-nginx": "Cloudflare", "amazon elb": "Amazon ELB", "awselb": "Amazon ELB",
    "elb": "Amazon ELB", "amazons3": "Amazon S3", "amazon s3": "Amazon S3", "s3": "Amazon S3",
    "amazon web services": "Amazon Web Services", "aws": "Amazon Web Services", "amazon ec2": "Amazon EC2",
    "google cloud": "Google Cloud", "google cloud platform": "Google Cloud", "gcp": "Google Cloud", "google": "Google Cloud",
    "microsoft azure": "Microsoft Azure", "azure": "Microsoft Azure", "windows azure": "Microsoft Azure",
    "jquery": "jQuery", "jquery ui": "jQuery UI", "jquery-ui": "jQuery UI", "jquery migrate": "jQuery Migrate",
    "twitter bootstrap": "Bootstrap", "bootstrap": "Bootstrap", "node.js": "Node.js", "nodejs": "Node.js", "node": "Node.js",
    "express": "Express", "expressjs": "Express", "express.js": "Express", "php": "PHP", "python": "Python",
    "ruby": "Ruby", "ruby on rails": "Ruby on Rails", "rails": "Ruby on Rails", "java": "Java", "golang": "Go", "go": "Go",
    "asp.net": "ASP.NET", "microsoft asp.net": "ASP.NET", ".net": ".NET", "dotnet": ".NET", "asp.net core": ".NET",
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "laravel": "Laravel", "symfony": "Symfony",
    "cakephp": "CakePHP", "phpcake": "CakePHP", "codeigniter": "CodeIgniter", "yii": "Yii", "zend": "Zend",
    "zend framework": "Zend", "kohana": "Kohana", "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
    "joomla!": "Joomla", "magento": "Magento", "unix": "Unix", "linux": "Linux", "debian": "Debian", "ubuntu": "Ubuntu",
    "centos": "CentOS", "red hat": "Red Hat", "redhat": "Red Hat", "rhel": "Red Hat", "red hat enterprise linux": "Red Hat",
    "fedora": "Fedora", "amazon linux": "Amazon Linux", "amzn": "Amazon Linux", "win32": "Windows", "win64": "Windows",
    "windows": "Windows", "windows server": "Windows Server", "freebsd": "FreeBSD", "openbsd": "OpenBSD", "alpine": "Alpine",
    "alpine linux": "Alpine", "suse": "SUSE", "opensuse": "SUSE", "oracle linux": "Oracle Linux", "rocky": "Rocky Linux",
    "rocky linux": "Rocky Linux", "almalinux": "AlmaLinux", "alma linux": "AlmaLinux", "raspbian": "Raspbian",
    "openssl": "OpenSSL", "mod_ssl": "mod_ssl", "mod-ssl": "mod_ssl", "openssh": "OpenSSH", "ssh": "OpenSSH",
    "google-analytics": "Google Analytics", "google analytics": "Google Analytics", "google-tag-manager": "Google Tag Manager",
    "google tag manager": "Google Tag Manager", "google-search-appliance": "Google Search Appliance",
    "fortinet-firewall": "Fortinet", "fortinet": "Fortinet", "fortigate": "FortiGate", "fortiweb": "Fortinet",
    "f5 big-ip": "F5 BIG-IP", "big-ip": "F5 BIG-IP", "bigip": "F5 BIG-IP", "imperva": "Imperva", "incapsula": "Incapsula",
    "sucuri": "Sucuri", "akamai": "Akamai", "akamaighost": "Akamai", "fastly": "Fastly", "varnish": "Varnish",
    "haproxy": "HAProxy", "envoy": "Envoy", "traefik": "Traefik", "kong": "Kong", "kong-gateway": "Kong", "squid": "Squid",
    "vercel": "Vercel", "netlify": "Netlify", "heroku": "Heroku", "fly.io": "Fly.io", "fly": "Fly.io", "github pages": "GitHub Pages",
    "github.io": "GitHub Pages", "digitalocean": "DigitalOcean", "firebase": "Firebase", "firebase hosting": "Firebase Hosting",
    "wp engine": "WP Engine", "wpengine": "WP Engine", "pantheon": "Pantheon", "hubspot": "HubSpot", "webflow": "Webflow",
    "wix": "Wix", "squarespace": "Squarespace", "shopify": "Shopify", "salesforce": "Salesforce", "marketo": "Marketo",
    "zendesk": "Zendesk", "intercom": "Intercom", "okta": "Okta", "statuspage": "Atlassian Statuspage",
    "readme": "ReadMe", "readme.io": "ReadMe", "gitbook": "GitBook", "sendgrid": "SendGrid", "mailgun": "Mailgun",
    "mailchimp": "Mailchimp", "caddy": "Caddy", "uvicorn": "uvicorn", "gunicorn": "Gunicorn", "uwsgi": "uWSGI",
    "werkzeug": "Werkzeug", "kestrel": "Kestrel", "phusion passenger": "Phusion Passenger", "passenger": "Phusion Passenger",
    "puma": "Puma", "tornadoserver": "Tornado", "tornado": "Tornado", "cowboy": "Cowboy", "webrick": "WEBrick",
    "lighttpd": "lighttpd", "uploadserver": "UploadServer", "ceph-dashboard": "Ceph-Dashboard", "ceph": "Ceph",
    "zabbix": "Zabbix", "grafana": "Grafana", "kibana": "Kibana", "jenkins": "Jenkins", "n8n": "n8n", "nagios": "Nagios",
    "cacti": "Cacti", "portainer": "Portainer", "sonarqube": "SonarQube", "swagger ui": "Swagger UI", "swagger-ui": "Swagger UI",
    "roundcube": "Roundcube", "zimbra": "Zimbra", "outlook web app": "Outlook Web App", "owa": "Outlook Web App",
    "microsoft exchange": "Microsoft Exchange", "exchange": "Microsoft Exchange", "fusionpbx": "FusionPBX", "freepbx": "FreePBX",
    "asterisk": "Asterisk", "freeswitch": "FreeSWITCH", "cpanel": "cPanel", "plesk": "Plesk", "webmin": "Webmin",
    "phpmyadmin": "phpMyAdmin", "nextcloud": "Nextcloud", "owncloud": "ownCloud",
    "gitlab": "GitLab", "gitea": "Gitea", "confluence": "Confluence", "jira": "Jira", "bitbucket": "Bitbucket",
    "mediawiki": "MediaWiki", "dokuwiki": "DokuWiki", "moodle": "Moodle", "ghost": "Ghost", "typo3": "TYPO3",
    "react": "React", "reactjs": "React", "vue": "Vue.js", "vue.js": "Vue.js", "vuejs": "Vue.js", "angular": "Angular",
    "angularjs": "AngularJS", "ember.js": "Ember.js", "ember": "Ember.js", "svelte": "Svelte", "backbone.js": "Backbone.js",
    "backbone": "Backbone.js", "next.js": "Next.js", "nextjs": "Next.js", "nuxt.js": "Nuxt.js", "nuxt": "Nuxt.js",
    "gatsby": "Gatsby", "blazor": "Blazor", "spring": "Spring", "spring boot": "Spring", "struts": "Struts", "struts2": "Struts",
    "play": "Play", "phoenix": "Phoenix", "modernizr": "Modernizr", "lodash": "Lodash", "underscore.js": "Underscore.js",
    "underscore": "Underscore.js", "moment.js": "Moment.js", "momentjs": "Moment.js", "font awesome": "Font Awesome",
    "fontawesome": "Font Awesome", "handlebars": "Handlebars", "prototype": "Prototype", "yui": "YUI", "mootools": "MooTools",
    "dojo": "Dojo", "ext js": "Ext JS", "extjs": "Ext JS", "select2": "Select2", "slick": "Slick", "swiper": "Swiper",
    "chart.js": "Chart.js", "d3": "D3", "d3.js": "D3", "highcharts": "Highcharts", "core-js": "core-js", "webpack": "webpack",
    "vite": "Vite", "requirejs": "RequireJS", "popper": "Popper", "popper.js": "Popper", "animate.css": "Animate.css",
    "tailwind css": "Tailwind CSS", "tailwindcss": "Tailwind CSS", "tailwind": "Tailwind CSS", "foundation": "Foundation",
    "semantic ui": "Semantic UI", "bulma": "Bulma", "google font api": "Google Font API", "google fonts": "Google Font API",
    "socket.io": "Socket.io", "axios": "Axios", "sentry": "Sentry", "tinymce": "TinyMCE", "ckeditor": "CKEditor",
    "datatables": "DataTables", "owl carousel": "Owl Carousel", "fancybox": "FancyBox", "isotope": "Isotope", "wow": "WOW",
    "google maps": "Google Maps", "youtube": "YouTube", "vimeo": "Vimeo", "recaptcha": "reCAPTCHA", "hcaptcha": "hCaptcha",
    "stripe": "Stripe", "paypal": "PayPal", "hotjar": "Hotjar", "segment": "Segment", "mixpanel": "Mixpanel",
    "new relic": "New Relic", "newrelic": "New Relic", "datadog": "Datadog", "facebook pixel": "Facebook Pixel",
    "linkedin insight tag": "LinkedIn Insight Tag", "pardot": "Pardot", "marketo munchkin": "Marketo Munchkin",
    "microsoft clarity": "Microsoft Clarity", "amplitude": "Amplitude", "fullstory": "FullStory", "heap": "Heap",
    "pendo": "Pendo", "drift": "Drift", "open graph": "Open Graph", "open-graph-protocol": "Open Graph",
    "twitter cards": "Twitter Cards", "http/2": "HTTP/2", "http/3": "HTTP/3", "spdy": "SPDY", "websocket": "WebSocket",
    "pwa": "PWA", "mysql": "MySQL", "mariadb": "MariaDB", "postgresql": "PostgreSQL", "postgres": "PostgreSQL",
    "mongodb": "MongoDB", "redis": "Redis", "memcached": "Memcached", "elasticsearch": "Elasticsearch", "opensearch": "OpenSearch",
    "rabbitmq": "RabbitMQ", "kafka": "Kafka", "minio": "MinIO", "docker": "Docker", "kubernetes": "Kubernetes",
    "bind": "BIND", "powerdns": "PowerDNS", "proftpd": "ProFTPD", "vsftpd": "vsftpd", "pure-ftpd": "Pure-FTPd", "samba": "Samba",
    "postfix": "Postfix", "exim": "Exim", "sendmail": "Sendmail", "dovecot": "Dovecot", "keycloak": "Keycloak", "auth0": "Auth0",
    "let's encrypt": "Let's Encrypt", "letsencrypt": "Let's Encrypt", "digicert": "DigiCert", "mod_perl": "mod_perl",
    "mod_python": "mod_python", "mod_wsgi": "mod_wsgi", "mod_jk": "mod_jk", "mod_fcgid": "mod_fcgid", "mod_pagespeed": "mod_pagespeed",
    "mod_auth_kerb": "mod_auth_kerb", "perl": "Perl", "lua": "Lua", "scala": "Scala", "coldfusion": "ColdFusion",
    "erlang": "Erlang", "elixir": "Elixir", "kotlin": "Kotlin", "google cloud armor": "Google Cloud Armor",
    "google cloud app armor": "Google Cloud Armor", "aws waf": "AWS WAF", "amazon waf": "AWS WAF",
    "aws elastic load balancer": "Amazon ELB", "azure front door": "Azure Front Door", "stackpath": "StackPath",
    "keycdn": "KeyCDN", "bunnycdn": "BunnyCDN", "jsdelivr": "jsDelivr", "cdnjs": "cdnjs", "unpkg": "unpkg",
    "google cloud load balancing": "Google Cloud Load Balancing", "azure application gateway": "Azure Application Gateway",
    "istio": "Istio", "zuul": "Zuul", "apigee": "Apigee", "pound": "Pound", "tyk": "Tyk", "linode": "Linode", "render": "Render",
    "railway": "Railway", "ovh": "OVH", "hetzner": "Hetzner", "rackspace": "Rackspace", "amazon api gateway": "Amazon API Gateway",
    "azure app service": "Azure App Service", "google app engine": "Google App Engine", "kinsta": "Kinsta",
    "microsoft sql server": "Microsoft SQL Server", "mssql": "Microsoft SQL Server", "oracle database": "Oracle Database",
    "smpp": "SMPP", "sip": "SIP", "rtp": "RTP", "odoo": "Odoo", "sugarcrm": "SugarCRM", "suitecrm": "SuiteCRM",
    "mautic": "Mautic", "matomo": "Matomo", "piwik": "Matomo", "osticket": "osTicket", "mantisbt": "MantisBT", "redmine": "Redmine",
    "concrete cms": "Concrete CMS", "concrete5": "Concrete CMS", "umbraco": "Umbraco", "sitecore": "Sitecore",
    "craft cms": "Craft CMS", "contentful": "Contentful", "woocommerce": "WooCommerce", "hugo": "Hugo", "jekyll": "Jekyll",
    "docusaurus": "Docusaurus", "nestjs": "NestJS", "koa": "Koa", "hapi": "Hapi", "sails.js": "Sails.js", "slim": "Slim",
    "lumen": "Lumen", "bottle": "Bottle", "pyramid": "Pyramid", "sinatra": "Sinatra", "grails": "Grails", "vaadin": "Vaadin",
    "jsf": "JSF", "meteor": "Meteor", "hypercorn": "Hypercorn", "daphne": "Daphne", "wildfly": "WildFly", "jboss": "JBoss",
    "weblogic": "WebLogic", "websphere": "WebSphere", "glassfish": "GlassFish", "mongrel": "Mongrel", "thin": "Thin",
    "unicorn": "Unicorn", "material design lite": "Material Design Lite", "materialize css": "Materialize CSS",
    "vuetify": "Vuetify", "element ui": "Element UI", "ant design": "Ant Design", "mui": "MUI", "emotion": "Emotion",
    "styled-components": "styled-components", "hammer.js": "Hammer.js", "gsap": "GSAP", "three.js": "Three.js",
    "lightbox": "Lightbox", "polyfill": "Polyfill", "google ads": "Google Ads", "twitter ads": "Twitter Ads",
    "hubspot analytics": "HubSpot Analytics", "openid": "OpenID", "saml": "SAML", "barracuda": "Barracuda",
    "cloudflare waf": "Cloudflare WAF", "azure cdn": "Azure CDN", "google cloud cdn": "Google Cloud CDN",
}

# whatweb plugin names that are HTTP header flags or response metadata, not technologies.
HEADER_FLAGS = {
    "hsts", "strict-transport-security", "httponly", "x-frame-options", "x-xss-protection", "x-ua-compatible",
    "x-content-type-options", "content-security-policy", "x-powered-by", "poweredby", "uncommonheaders", "cookies",
    "email", "script", "html5", "meta-author", "open-graph-protocol", "frame", "passwordfield", "redirectlocation",
    "via-proxy", "probably", "title", "ip", "country", "httpserver", "metagenerator", "index-of", "content-language",
    "access-control-allow-methods", "www-authenticate", "meta-refresh-redirect", "x-pingback", "x-aspnet-version",
    "x-aspnetmvc-version", "cache-control", "etag", "object", "iframe", "doctype", "html", "contact", "phone",
    "x-robots-tag", "expires", "pragma", "vary", "p3p", "x-cache", "x-varnish", "x-served-by", "age", "lastmodified",
    "x-powered-by-plesk", "set-cookie", "x-mod-pagespeed", "x-page-speed", "transfer-encoding", "x-forwarded-for",
}

# Tokens that only describe a response, not a technology (from httpx/Wappalyzer and whatweb strings).
JUNK_NAMES = {"hsts", "index-of", "httponly", "x-ua-compatible", "basic", "digest", "ntlm", "negotiate", "bearer",
              "us", "united states", "unknown", "none", "null", "n/a", "-", "", "generic"}

OS_RANK = {"Unix": 1, "Linux": 2, "Windows": 3, "Windows Server": 4, "FreeBSD": 5, "OpenBSD": 5, "Debian": 6, "Ubuntu": 6,
           "CentOS": 6, "Red Hat": 6, "Fedora": 6, "Amazon Linux": 6, "Alpine": 6, "SUSE": 6, "Oracle Linux": 6,
           "Rocky Linux": 6, "AlmaLinux": 6, "Raspbian": 6, "macOS": 6}

# endoflife.date product slugs for the components that carry versions.
EOL_PRODUCTS = {
    "PHP": "php", "Apache": "apache", "nginx": "nginx", "OpenSSL": "openssl", "Node.js": "nodejs", "Python": "python",
    "Ruby": "ruby", "Tomcat": "tomcat", "Django": "django", "Ruby on Rails": "rails", "Ubuntu": "ubuntu",
    "Debian": "debian", "CentOS": "centos", "Windows Server": "windows-server", "Drupal": "drupal", "WordPress": "wordpress",
    "jQuery": "jquery", "Bootstrap": "bootstrap", "Angular": "angular", "Laravel": "laravel", "Express": "express",
    "React": "react", "Vue.js": "vue", "Next.js": "nextjs", "Kong": "kong-gateway", "Go": "go", "Varnish": "varnish",
    "Zabbix": "zabbix", "Grafana": "grafana", "Jenkins": "jenkins", "Elasticsearch": "elasticsearch", "Symfony": "symfony",
    "Magento": "magento", "Joomla": "joomla", "Alpine": "alpine", "Amazon Linux": "amazon-linux", "Red Hat": "rhel",
    "FreeBSD": "freebsd", "Fedora": "fedora", "Rocky Linux": "rocky-linux", "AlmaLinux": "almalinux", ".NET": "dotnet",
    "Spring": "spring-framework", "Envoy": "envoy", "HAProxy": "haproxy", "Traefik": "traefik", "Kibana": "kibana",
    "Redis": "redis", "MySQL": "mysql", "MariaDB": "mariadb", "PostgreSQL": "postgresql", "MongoDB": "mongodb",
    "OpenSearch": "opensearch", "RabbitMQ": "rabbitmq", "Nextcloud": "nextcloud", "GitLab": "gitlab", "Moodle": "moodle",
    "MediaWiki": "mediawiki", "Perl": "perl", "Java": "oracle-jdk", "Kubernetes": "kubernetes", "Docker": "docker-engine",
    "Memcached": "memcached", "Keycloak": "keycloak", "Confluence": "confluence",
    "Jira": "jira-software", "Bitbucket": "bitbucket", "Squid": "squid", "Postfix": "postfix", "Erlang": "erlang", "Elixir": "elixir", "Scala": "scala", "Kotlin": "kotlin", "ColdFusion": "coldfusion",
    "Jetty": "eclipse-jetty", "Nuxt.js": "nuxt", "Umbraco": "umbraco",
    "TYPO3": "typo3", "Matomo": "matomo",
}

_VER = re.compile(r"^v?(\d+(?:\.\d+){0,3}[a-z0-9.\-+~]*)$", re.I)
_HOSTLIKE = re.compile(r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)
_OS_PAREN = {"unix": "Unix", "linux": "Linux", "debian": "Debian", "ubuntu": "Ubuntu", "centos": "CentOS", "red hat": "Red Hat",
             "redhat": "Red Hat", "rhel": "Red Hat", "fedora": "Fedora", "amazon": "Amazon Linux", "amazon linux": "Amazon Linux",
             "win32": "Windows", "win64": "Windows", "windows": "Windows", "freebsd": "FreeBSD", "openbsd": "OpenBSD",
             "alpine": "Alpine", "suse": "SUSE", "raspbian": "Raspbian", "darwin": "macOS", "rocky": "Rocky Linux",
             "almalinux": "AlmaLinux", "oracle": "Oracle Linux"}


def canonical(name):
    """Fold a raw technology name onto the catalog spelling (or return it stripped if unknown)."""
    s = (name or "").strip().strip("\"'").rstrip(".;,")
    if not s:
        return ""
    key = s.lower()
    if key in ALIASES:
        return ALIASES[key]
    # "Apache/2" style without version was split before; "nginx (Ubuntu)" etc.
    key2 = re.sub(r"\s*\(.*?\)\s*", "", key).strip()
    if key2 in ALIASES:
        return ALIASES[key2]
    for cname in CATALOG:
        if cname.lower() == key2:
            return cname
    return s


def category_of(name):
    c = CATALOG.get(name)
    if c:
        return c
    k = name.lower()
    if k.endswith(".js") or "jquery" in k or k.endswith("js"):
        return "js_library"
    if k.startswith("mod_"):
        return "service"
    if k.endswith(" cms") or k.endswith("cms"):
        return "cms"
    return "other"


def is_junk(name):
    k = (name or "").strip().lower()
    if not k or k in JUNK_NAMES or k in HEADER_FLAGS:
        return True
    try:
        ipaddress.ip_address(k.strip("[]"))
        return True
    except ValueError:
        pass
    if _HOSTLIKE.fullmatch(k) and k not in ALIASES and not any(c.lower() == k for c in CATALOG):
        return True
    if not re.search(r"[a-z]", k):
        return True
    if re.fullmatch(r"[0-9a-f]{16,}", k):          # hashes, cf-ray ids
        return True
    if len(k) > 80:
        return True
    return False


def split_name_version(token):
    """'PHP:5.4.45' / 'PHP/5.4.45' / 'PHP 5.4.45' / 'Apache HTTP Server:2.2.34' -> ('Apache', '2.2.34')."""
    t = (token or "").strip()
    if not t:
        return "", None
    m = re.match(r"^(.*?)[:/ ]v?(\d+(?:\.\d+){0,3}[A-Za-z0-9.\-+~]*)$", t)
    if m and m.group(1).strip():
        return canonical(m.group(1)), m.group(2)
    return canonical(t), None


def parse_server_header(value):
    """Server / X-Powered-By header -> [(name, version, source_note)] plus OS hints from parentheticals."""
    out = []
    s = (value or "").strip()
    if not s:
        return out
    # parentheticals carry the OS ("(Unix)", "(Debian)", "(Ubuntu)", "(Win64)") or a repo ("(IUS)"), both ignored
    for par in re.findall(r"\(([^)]*)\)", s):
        p = par.strip().lower()
        for key, osname in _OS_PAREN.items():
            if p == key or p.startswith(key + " ") or p.startswith(key + "/"):
                out.append((osname, None, "server-header"))
                break
    body = re.sub(r"\([^)]*\)", " ", s).strip()
    whole, wver = split_name_version(body)
    if whole in CATALOG and " " in body:
        out.append((whole, wver, "server-header"))
        return out
    for tok in body.split():
        name, ver = split_name_version(tok)
        if not name or is_junk(name):
            continue
        out.append((name, ver, "server-header"))
    return out


def _add(comps, category, name, version, source, evidence):
    if not name or is_junk(name):
        return
    key = (category, name, version or "")
    cur = comps.get(key)
    if cur is None:
        comps[key] = {"category": category, "name": name, "version": version or None, "source": source, "evidence": evidence}
    elif source not in cur["source"].split("+"):
        cur["source"] = cur["source"] + "+" + source


def _component(comps, raw_name, version, source, evidence, category=None):
    name = canonical(raw_name)
    if not name or is_junk(name):
        return
    if version is None and name not in CATALOG:
        name, version = split_name_version(name)
        name = canonical(name)
    cat = category or category_of(name)
    _add(comps, cat, name, version, source, evidence)


def normalize(ev):
    """Evidence bundle -> sorted list of components. See the module docstring for the bundle keys."""
    comps = {}
    # httpx (Wappalyzer fingerprints + Server header + TLS)
    for ep in ev.get("endpoints") or []:
        for t in ep.get("tech") or []:
            _component(comps, t, None, "httpx", "tech-detect")
        for name, ver, note in parse_server_header(ep.get("server")):
            _component(comps, name, ver, "httpx", note)
        for c in ep.get("cpe") or []:
            prod = c.get("product") if isinstance(c, dict) else None
            if prod:
                _component(comps, prod, None, "httpx", "cpe")
        tls = ep.get("tls") or {}
        if tls.get("tls_version"):
            _add(comps, "tls", _tls_label(tls["tls_version"]), None, "httpx", "negotiated")
        iss = tls.get("issuer_org") or tls.get("issuer_cn")
        if isinstance(iss, list):
            iss = iss[0] if iss else None
        if iss:
            _add(comps, "tls", "Issuer: " + _issuer_label(iss), None, "httpx", "certificate")
        cdn = (ep.get("cdn_name") or "").lower()
        ctype = (ep.get("cdn_type") or "").lower()
        if cdn and ctype in ("cdn", "waf"):
            _component(comps, cdn, None, "httpx", "cdn-check", "cdn" if ctype == "cdn" else "waf")
        elif cdn and ctype == "cloud":
            _component(comps, cdn, None, "httpx", "cdn-check", "hosting")
    # whatweb plugins (names + versions + a few informative string values)
    for plug, body in (ev.get("whatweb") or {}).items():
        body = body or {}
        pk = plug.lower()
        if pk in ("httpserver",):
            for s in body.get("string") or []:
                for name, ver, note in parse_server_header(s):
                    _component(comps, name, ver, "whatweb", "server-header")
            continue
        if pk in ("x-powered-by", "poweredby"):
            for s in body.get("string") or []:
                for name, ver, note in parse_server_header(s):
                    _component(comps, name, ver, "whatweb", "x-powered-by")
            continue
        if pk == "metagenerator":
            for s in body.get("string") or []:
                name, ver = split_name_version(s)
                _component(comps, name, ver, "whatweb", "meta-generator")
            continue
        if pk in HEADER_FLAGS:
            continue
        versions = body.get("version") or []
        if versions:
            for v in versions:
                _component(comps, plug, str(v), "whatweb", "plugin")
        else:
            _component(comps, plug, None, "whatweb", "plugin")
        if pk == "os":
            for s in body.get("string") or []:
                _component(comps, s, None, "whatweb", "os-plugin", "os")
    # wafw00f
    if ev.get("waf") and ev["waf"].lower() not in JUNK_NAMES:
        wname = canonical(ev["waf"])
        wcat = CATALOG.get(wname)
        _component(comps, wname, None, "wafw00f", "detected", wcat if wcat in ("waf", "cdn", "load_balancer") else "waf")
    # nuclei info-level fingerprint templates
    for t in ev.get("nuclei") or []:
        tid = (t.get("template") or "").lower()
        vals = [str(v) for v in (t.get("extracted") or [])[:8]]
        if tid in ("tech-detect", "fingerprinthub-web-fingerprints", "favicon-detect", "waf-detect"):
            names = vals or ([t.get("matcher")] if t.get("matcher") else [])
            for n in names:
                _component(comps, n, None, "nuclei", tid, "waf" if tid == "waf-detect" else None)
        elif tid in ("dns-saas-service-detection", "ec2-detection", "aws-detect", "azure-domain-tenant", "ssl-issuer"):
            names = vals or ([t.get("matcher")] if t.get("matcher") else [])
            for n in names:
                if tid == "ssl-issuer":
                    _add(comps, "tls", "Issuer: " + _issuer_label(n), None, "nuclei", tid)
                else:
                    _component(comps, n, None, "nuclei", tid, "hosting")
        elif tid in ("tls-version",):
            for n in vals:
                _add(comps, "tls", _tls_label(n), None, "nuclei", tid)
        elif t.get("matcher") and tid.endswith("-detect"):
            _component(comps, t["matcher"], None, "nuclei", tid)
        # other DNS templates (aaaa-fingerprint, dns-rebinding, caa/mx/txt fingerprints...) carry addresses and
        # record values, never a technology: ignored on purpose.
    # nmap banners (behind NAT or a filtering firewall many services show as tcpwrapped; parse what came back)
    for p in ev.get("nmap") or []:
        prod = (p.get("product") or "").strip()
        if prod:
            name, ver = split_name_version(prod.replace(" httpd", ""))
            _component(comps, name, ver, "nmap", f"service:{p.get('port')}")
        banner = ((p.get("scripts") or {}).get("banner") or "").strip()
        m = re.match(r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)(?:\s+(\S+))?", banner)
        if m:
            _component(comps, "OpenSSH", m.group(1), "nmap", "ssh-banner")
            tail = (m.group(2) or "").lower()
            for key, osname in _OS_PAREN.items():
                if tail.startswith(key):
                    _component(comps, osname, None, "nmap", "ssh-banner", "os")
                    break
    # sslscan
    ssl = ev.get("sslscan") or {}
    for pr in ssl.get("protocols") or []:
        _add(comps, "tls", _tls_label(pr), None, "sslscan", "enabled")
    if ssl.get("issuer"):
        _add(comps, "tls", "Issuer: " + _issuer_label(ssl["issuer"]), None, "sslscan", "certificate")
    # DNS: CNAME targets name the platform
    for cn in ev.get("cnames") or []:
        label = provider_from_cname(cn, ev.get("third_party_suffixes") or ())
        if label:
            _component(comps, label, None, "cname", cn, "hosting")
    asn = ev.get("asn") or {}
    if asn.get("as_name"):
        label = provider_from_asn(asn["as_name"])
        if label:
            _component(comps, label, None, "asn", f"AS{asn.get('asn')} {asn['as_name']}", "hosting")
    return sorted(comps.values(), key=lambda c: (CATEGORIES.index(c["category"]), c["name"].lower(), c["version"] or ""))


def _tls_label(v):
    s = str(v or "").strip().lower().replace(" ", "")
    m = {"tls13": "TLS 1.3", "tls12": "TLS 1.2", "tls11": "TLS 1.1", "tls10": "TLS 1.0", "tlsv1.3": "TLS 1.3", "tlsv1.2": "TLS 1.2",
         "tlsv1.1": "TLS 1.1", "tlsv1.0": "TLS 1.0", "tls1.3": "TLS 1.3", "tls1.2": "TLS 1.2", "tls1.1": "TLS 1.1", "tls1.0": "TLS 1.0",
         "tls1": "TLS 1.0", "ssl3": "SSL 3.0", "sslv3": "SSL 3.0", "ssl2": "SSL 2.0", "sslv2": "SSL 2.0", "ssl3.0": "SSL 3.0", "ssl2.0": "SSL 2.0"}
    return m.get(s, str(v).strip())


def _issuer_label(s):
    s = str(s or "").strip()
    s = re.sub(r"\s+(Inc\.?|LLC|Ltd\.?|Limited|Corporation|Corp\.?|GmbH|S\.A\.|Co\.)$", "", s.rstrip(","), flags=re.I).strip(" ,")
    s = re.sub(r"^(Gateway CA|Cloudflare Managed).*", "Cloudflare", s, flags=re.I)
    # intermediate CN only (older httpx rows carry no issuer_org): Let's Encrypt R*/E*/YR*/YE*, Google Trust Services WR*/WE*
    if re.fullmatch(r"(R|E|YR|YE)\d{1,2}", s):
        return "Let's Encrypt"
    if re.fullmatch(r"W[RE]\d{1,2}", s):
        return "Google Trust Services"
    if is_junk(s) or re.fullmatch(r"[0-9a-f-]{32,36}", s.lower()) or "fake certificate" in s.lower() or len(s) < 4:
        return "Private / self-signed"
    for a, b in (("let's encrypt", "Let's Encrypt"), ("amazon", "Amazon"), ("digicert", "DigiCert"), ("sectigo", "Sectigo"),
                 ("go daddy", "GoDaddy"), ("geotrust", "GeoTrust"), ("thawte", "Thawte"), ("rapidssl", "RapidSSL"), ("usertrust", "Sectigo"),
                 ("comodo", "Sectigo"), ("globalsign", "GlobalSign"), ("godaddy", "GoDaddy"), ("google trust", "Google Trust Services"),
                 ("cloudflare", "Cloudflare"), ("entrust", "Entrust"), ("zerossl", "ZeroSSL"), ("starfield", "Starfield"),
                 ("microsoft", "Microsoft"), ("buypass", "Buypass"), ("ssl.com", "SSL.com"), ("certum", "Certum")):
        if a in s.lower():
            return b
    return s[:60] or "unknown"


CNAME_PROVIDERS = (
    ("elb.amazonaws.com", "AWS ELB"), ("awsglobalaccelerator.com", "AWS Global Accelerator"), ("cloudfront.net", "AWS CloudFront"),
    ("amazonaws.com", "AWS"), ("awsapprunner.com", "AWS App Runner"), ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("execute-api", "AWS API Gateway"), ("s3-website", "AWS S3"), ("herokuapp.com", "Heroku"), ("herokudns.com", "Heroku"),
    ("azurewebsites.net", "Azure App Service"), ("azureedge.net", "Azure CDN"), ("azurefd.net", "Azure Front Door"),
    ("trafficmanager.net", "Azure Traffic Manager"), ("cloudapp.azure.com", "Azure"), ("cloudapp.net", "Azure"), ("windows.net", "Azure"),
    ("azure-api.net", "Azure API Management"), ("ghs.googlehosted.com", "Google"), ("googlehosted.com", "Google"),
    ("ghs.google.com", "Google"), ("appspot.com", "Google App Engine"), ("run.app", "Google Cloud Run"), ("web.app", "Firebase"),
    ("firebaseapp.com", "Firebase"), ("storage.googleapis.com", "Google Cloud Storage"), ("cloudflare.net", "Cloudflare"),
    ("cdn.cloudflare.net", "Cloudflare"), ("cloudflare-ipfs.com", "Cloudflare"), ("fly.dev", "Fly.io"), ("vercel.app", "Vercel"),
    ("vercel-dns.com", "Vercel"), ("netlify.app", "Netlify"), ("netlify.com", "Netlify"), ("github.io", "GitHub Pages"),
    ("gitlab.io", "GitLab Pages"), ("wpengine.com", "WP Engine"), ("wpenginepowered.com", "WP Engine"), ("pantheonsite.io", "Pantheon"),
    ("kinsta.cloud", "Kinsta"), ("squarespace.com", "Squarespace"), ("wixdns.net", "Wix"), ("wixsite.com", "Wix"),
    ("myshopify.com", "Shopify"), ("shopify.com", "Shopify"), ("hubspot.net", "HubSpot"), ("hs-sites.com", "HubSpot"),
    ("hubspotpagebuilder.com", "HubSpot"), ("zendesk.com", "Zendesk"), ("freshdesk.com", "Freshdesk"), ("statuspage.io", "Atlassian Statuspage"),
    ("atlassian.net", "Atlassian"), ("force.com", "Salesforce"), ("salesforce.com", "Salesforce"), ("exacttarget.com", "Salesforce Marketing Cloud"),
    ("pardot.com", "Pardot"), ("marketo.com", "Marketo"), ("mktoweb.com", "Marketo"), ("mkto-", "Marketo"), ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"), ("mailchimp.com", "Mailchimp"), ("okta.com", "Okta"), ("oktapreview.com", "Okta"), ("auth0.com", "Auth0"),
    ("zoom.us", "Zoom"), ("docusign.net", "DocuSign"), ("intercom.io", "Intercom"), ("customer.io", "Customer.io"),
    ("unbounce.com", "Unbounce"), ("instapage.com", "Instapage"), ("webflow.io", "Webflow"), ("webflow.com", "Webflow"),
    ("readme.io", "ReadMe"), ("gitbook.io", "GitBook"), ("helpscoutdocs.com", "Help Scout"), ("greenhouse.io", "Greenhouse"),
    ("lever.co", "Lever"), ("workable.com", "Workable"), ("bamboohr.com", "BambooHR"), ("sharepoint.com", "Microsoft 365"),
    ("office.com", "Microsoft 365"), ("outlook.com", "Microsoft 365"), ("lync.com", "Microsoft 365"), ("webex.com", "Webex"),
    ("ringcentral.com", "RingCentral"), ("akadns.net", "Akamai"), ("akamaiedge.net", "Akamai"), ("edgekey.net", "Akamai"),
    ("edgesuite.net", "Akamai"), ("fastly.net", "Fastly"), ("fastlylb.net", "Fastly"), ("incapdns.net", "Imperva"),
    ("impervadns.net", "Imperva"), ("sucuri.net", "Sucuri"), ("digitaloceanspaces.com", "DigitalOcean"), ("ondigitalocean.app", "DigitalOcean"),
    ("linodeobjects.com", "Linode"), ("onrender.com", "Render"), ("railway.app", "Railway"), ("twilio.com", "Twilio"),
    ("sinch.com", "Sinch"), ("bandwidth.com", "Bandwidth"), ("vonage.com", "Vonage"), ("nexmo.com", "Vonage"),
)


def provider_from_cname(cname, extra_suffixes=()):
    c = (cname or "").lower().rstrip(".")
    if not c:
        return None
    for suf, label in CNAME_PROVIDERS:
        if c.endswith(suf) or ("." + suf) in c or (suf.endswith("-") and suf in c):
            return label
    for suf in extra_suffixes:
        s = (suf or "").lower().strip()
        if s and (c == s or c.endswith("." + s)):
            # unknown vendor from the third-party CNAME list: name it by its registrable part
            parts = s.split(".")
            return parts[-2].capitalize() if len(parts) >= 2 else s
    return None


ASN_PROVIDERS = (
    ("amazon", "AWS"), ("aws", "AWS"), ("google", "Google Cloud"), ("gcp", "Google Cloud"), ("microsoft", "Azure"), ("azure", "Azure"),
    ("cloudflare", "Cloudflare"), ("akamai", "Akamai"), ("fastly", "Fastly"), ("digitalocean", "DigitalOcean"), ("linode", "Linode"),
    ("akamai", "Akamai"), ("ovh", "OVH"), ("hetzner", "Hetzner"), ("rackspace", "Rackspace"), ("oracle", "Oracle Cloud"),
    ("ibm", "IBM Cloud"), ("softlayer", "IBM Cloud"), ("vultr", "Vultr"), ("fly.io", "Fly.io"), ("flyio", "Fly.io"),
    ("salesforce", "Salesforce"), ("sendgrid", "SendGrid"), ("twilio", "Twilio"), ("zoom", "Zoom"), ("webflow", "Webflow"),
    ("marketo", "Marketo"), ("hubspot", "HubSpot"), ("wix", "Wix"), ("squarespace", "Squarespace"), ("shopify", "Shopify"),
    ("github", "GitHub"), ("eircom", "Eircom"),
    ("cogent", "Cogent transit"), ("level 3", "Lumen transit"), ("lumen", "Lumen transit"), ("zayo", "Zayo transit"),
    ("leaseweb", "Leaseweb"), ("godaddy", "GoDaddy"),
    ("bluehost", "Bluehost"), ("hostgator", "HostGator"), ("liquid web", "Liquid Web"), ("dreamhost", "DreamHost"),
    ("comcast", "Comcast"), ("verizon", "Verizon"), ("at&t", "AT&T"), ("charter", "Charter"), ("cox", "Cox"),
)


OWN_NETWORKS_FILE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "own_networks.txt"))


class OwnNetworksError(ValueError):
    """config/own_networks.txt cannot be used; the message names the file and the line."""


def load_own_networks(path=OWN_NETWORKS_FILE):
    """Your own networks and colos, matched against AS names before the generic providers above.

    One "substring<TAB>label" per line; blank lines and "#" comments are ignored. The substring is matched
    case-insensitively inside the AS name. A missing file means no own networks. A malformed line raises
    OwnNetworksError("<file>:<line>: ...")."""
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return ()
    except (OSError, UnicodeDecodeError) as e:
        raise OwnNetworksError(f"{path}: unreadable ({e})") from None
    for n, line in enumerate(lines, 1):
        line = line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        key, sep, label = line.partition("\t")
        if not sep or not key.strip() or not label.strip():
            raise OwnNetworksError(f"{path}:{n}: expected 'substring<TAB>label', got {line.strip()[:60]!r}")
        out.append((key.strip().lower(), label.strip()))
    return tuple(out)


OWN_NETWORKS = None   # loaded on first use by own_networks(), so a bad file never breaks an import


def own_networks():
    global OWN_NETWORKS
    if OWN_NETWORKS is None:
        OWN_NETWORKS = load_own_networks(OWN_NETWORKS_FILE)
    return OWN_NETWORKS


def provider_from_asn(as_name):
    s = (as_name or "").lower()
    if not s:
        return None
    for key, label in own_networks() + ASN_PROVIDERS:
        if key in s:
            return label
    # fall back to the organisation token before the country code ("FOO-AS, US" -> "FOO-AS")
    return as_name.split(",")[0].strip()[:40] or None


def hosting(ev):
    """Who hosts this host: (label, source). Order: the AWS inventory of accounts in scope, httpx cloud/CDN edge, CNAME platform, ASN."""
    cn = [c.lower().rstrip(".") for c in (ev.get("cnames") or [])]
    owned_aws = {x.lower().rstrip(".") for x in (ev.get("owned_aws") or ())}
    for c in cn:
        if c in owned_aws or c.replace("dualstack.", "") in owned_aws:
            label = provider_from_cname(c) or "AWS"
            return label + " (an account in scope)", "owned_aws"
    for c in cn:
        label = provider_from_cname(c, ev.get("third_party_suffixes") or ())
        if label:
            return label, "cname"
    for ep in ev.get("endpoints") or []:
        cdn = (ep.get("cdn_name") or "").lower(); ctype = (ep.get("cdn_type") or "").lower()
        if cdn and ctype in ("cdn", "waf", "cloud"):
            label = {"aws": "AWS", "cloudfront": "AWS CloudFront", "google": "Google Cloud", "azure": "Azure", "cloudflare": "Cloudflare",
                     "fastly": "Fastly", "akamai": "Akamai"}.get(cdn, cdn.capitalize())
            return label, "httpx"
    asn = ev.get("asn") or {}
    if asn.get("as_name"):
        return provider_from_asn(asn["as_name"]), "asn"
    for c in ev.get("_components") or []:
        if c["category"] == "hosting":
            return {"Amazon Web Services": "AWS", "Amazon S3": "AWS S3", "Amazon EC2": "AWS"}.get(c["name"], c["name"]), c["source"].split("+")[0]
    return None, None


def _pick(components, category, prefer_version=True):
    rows = [c for c in components if c["category"] == category]
    if not rows:
        return None
    if category == "os":
        rows.sort(key=lambda c: (-OS_RANK.get(c["name"], 0), c["version"] is None))
    else:
        rows.sort(key=lambda c: (c["version"] is None, c["name"].lower()))
    best = rows[0]
    return best["name"] + (f" {best['version']}" if best["version"] else "")


def profile(components, ev):
    """One row per host for the inventory table and CSV."""
    tls = [c["name"] for c in components if c["category"] == "tls" and not c["name"].startswith("Issuer:")]
    order = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
    known = sorted({t for t in tls if t in order}, key=order.index)
    issuer = next((c["name"][len("Issuer: "):] for c in components if c["category"] == "tls" and c["name"].startswith("Issuer:")), None)
    host_label, host_src = hosting({**ev, "_components": components})
    cdn = _pick(components, "cdn"); waf = _pick(components, "waf") or (canonical(ev["waf"]) if ev.get("waf") and ev["waf"].lower() not in JUNK_NAMES else None)
    lb = _pick(components, "load_balancer")
    cert_expiry = next((e["tls"]["not_after"] for e in (ev.get("endpoints") or []) if e.get("tls") and e["tls"].get("not_after")), None)
    asn = ev.get("asn") or {}
    eol_count = sum(1 for c in components if c.get("eol") == 1)
    return {
        "hosting": host_label, "hosting_source": host_src, "asn": asn.get("asn"), "as_name": asn.get("as_name"),
        "cdn": cdn, "waf": waf, "load_balancer": lb, "os": _pick(components, "os"), "web_server": _pick(components, "web_server"),
        "language": _pick(components, "language"), "framework": _pick(components, "framework"), "cms": _pick(components, "cms"),
        "tls_min": known[0] if known else None, "tls_max": known[-1] if known else None, "cert_issuer": issuer,
        "cert_expiry": cert_expiry, "eol_count": eol_count,
    }


# ------------------------------------------------------------------ end of life
def eol_cycle(version, cycles):
    """Longest-prefix match of a version against a product's endoflife.date cycle list."""
    v = (version or "").strip().lower().lstrip("v")
    if not v:
        return None
    best = None
    for c in cycles or []:
        cyc = str(c.get("cycle") or "").lower()
        if not cyc:
            continue
        if v == cyc or (v.startswith(cyc) and not v[len(cyc)].isdigit()):   # 5.4.45 -> 5.4, 1.0.2k -> 1.0.2, 22.04 -> 22.04
            if best is None or len(cyc) > len(str(best.get("cycle"))):
                best = c
    return best


def eol_status(name, version, eol_data, on_date):
    """(eol 0/1/None, eol_date or None). eol_data: {product_slug: [cycle dicts]}, on_date: datetime.date."""
    slug = EOL_PRODUCTS.get(name)
    if not slug or not version or slug not in (eol_data or {}):
        return None, None
    c = eol_cycle(version, eol_data[slug])
    if not c:
        return None, None
    e = c.get("eol")
    if e is True:
        return 1, None
    if e is False or e is None:
        return 0, None
    try:
        d = dt.date.fromisoformat(str(e)[:10])
    except ValueError:
        return None, None
    return (1 if d < on_date else 0), d.isoformat()


def _is_public(ip):
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return o.is_global
