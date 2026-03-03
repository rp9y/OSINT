# OSINT
An extremely simplified OSINT multitool made in python, available to everyone.

**NOTE: WE DO NOT TAKE ANY RESPONSIBILITY FOR WHAT YOU DO WITH THIS. THIS TOOL IS MADE FOR EDUCATIONAL PURPOSES ONLY.**

## Parts of the Tool

1️⃣ IP Geolocation

This option looks up information about an IP address. It shows details like country, city, ISP, and approximate location coordinates. It gathers data from multiple public IP information providers.

2️⃣ Phone Intelligence

This analyzes a phone number using the phonenumbers library. It shows formatting, country, carrier, time zones, and whether the number is valid. It also checks for a possible public Telegram presence.

3️⃣ Domain Analysis

This retrieves WHOIS and DNS records for a domain. It shows registrar details, creation and expiration dates, and name servers. It also checks DNS records like A, MX, NS, TXT, and more.

4️⃣ Breach Check

This checks whether an email address appears in known data breaches. It uses the Have I Been Pwned API to see if the email was exposed. It returns the names of breached services if found.

5️⃣ Discord Invite Info

This analyzes a public Discord invite code. It shows details about the server (guild), inviter, channel, and server features. It only works with public invite data.

6️⃣ Username Search

This checks if a username exists across many popular platforms. It sends quick requests to sites like Twitter/X, GitHub, Instagram, and others. If the profile exists, it lists the platform and profile URL.

7️⃣ Instagram Profile

This fetches public Instagram profile information. It shows full name, bio, follower count, following count, post count, and privacy status. It may fail if the account is private or rate-limited.

8️⃣ TikTok Profile

This retrieves public TikTok profile data by scraping the profile page. It shows nickname, user ID, verification status, bio, followers, and other statistics. It may fail if TikTok blocks the request.

9️⃣ URL Analysis

This checks a full URL and shows its HTTP status and final redirected URL. It also extracts the domain and performs domain analysis on it. This helps identify redirects and domain ownership details.
