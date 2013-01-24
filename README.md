GreasySpoon CaptchaWhitelist
============================

Allows access to non-whitelisted sites by solving a CAPTCHA, implemented as 
a GreasySpoon Java ICAP script. The script is in the repository at 
jar/serverscripts/CaptchaWhitelistScript.req.server.java

To ensure this is effective, clients must not be able to connect to any IP 
or make DNS requests bypassing the proxy, and the proxy should be set up to 
"bump" SSL (for example, see http://wiki.squid-cache.org/Features/SslBump)
or HTTPS connections will not be restricted to the whitelist.

CaptchaWhitelist was written using Apache Derby (required jar included) but 
should be able to use any database.

Configuration is in the CaptchaWhitelist.conf, an example of which is 
included. This repository should be cloned to /usr/local/GreasySpoon/ but 
can be anywhere if the configFileLocation in the script is changed.

------------------------------------------------

GreasySpoon is an Internet Content Adaptation Protocol (ICAP) server.
GreasySpoon is written Java and supports ICAP scripts written in JavaScript,
Java, and Ruby.

GreasySpoon is Copyright (C) 2008-2011 Karel MITTIG, released under an
AGPL-3.0 license.

The latest STABLE release of GreasySpoon can be downloaded from:
* http://greasyspoon.googlecode.com/files/greasyspoon-release-1.0.8.tar.gz
* http://greasyspoon.googlecode.com/files/greasyspoon-setup-1.0.8.exe
* http://greasyspoon.googlecode.com/files/greasyspoon-release-1.0.8-sources.tar.gz

The latest TESTING release can be downloaded from:
* http://greasyspoon.googlecode.com/files/greasyspoon-release-1.0.9.tar.gz
* http://greasyspoon.googlecode.com/files/greasyspoon-setup-1.0.9.exe

Extensions to enable Java and Ruby ICAP scripts can be downloaded from:
* http://greasyspoon.googlecode.com/files/java-1.0.1.gsx
* http://greasyspoon.googlecode.com/files/ruby-1.0.1.gsx

I believe the GreasySpoon team now sells a commercial ICAP Server with
support: L3WS Webflow Adapter (http://www.l3ws.com/).  They may be willing
to provide commercial support for GreasySpoon, as well.
