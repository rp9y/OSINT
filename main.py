import json
import sys
import requests
import phonenumbers
import dns.resolver
from urllib.parse import quote
from phonenumbers import geocoder, carrier, timezone
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
import whois
import instaloader

console = Console()

IP_PROVIDERS = [
    "http://ip-api.com/json/{}",
    "https://ipinfo.io/{}/json",
    "https://freeipapi.com/api/json/{}",
]

def fetch_json(url, method="GET", data=None, headers=None, timeout=10):
    headers = headers or {"User-Agent": "Mozilla/5.0"}
    try:
        if method == "POST":
            r = requests.post(url, json=data, headers=headers, timeout=timeout)
        else:
            r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def ip_lookup(ip):
    result = {"ip": ip, "providers": []}
    for prov in IP_PROVIDERS:
        data = fetch_json(prov.format(ip))
        if "error" not in data:
            result["providers"].append(data)
    if result["providers"]:
        agg = result["providers"][0]
        result.update({
            "country": agg.get("country"),
            "region": agg.get("regionName") or agg.get("region"),
            "city": agg.get("city"),
            "lat": agg.get("lat") or agg.get("latitude"),
            "lon": agg.get("lon") or agg.get("longitude"),
            "isp": agg.get("isp") or agg.get("org"),
            "asn": agg.get("as") or agg.get("asn"),
        })
    return result

def phone_lookup(number):
    result = {}
    try:
        parsed = phonenumbers.parse(number, None)
        result.update({
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "country": geocoder.description_for_number(parsed, "en"),
            "location": geocoder.description_for_valid_number(parsed, "en"),
            "carrier": carrier.name_for_number(parsed, "en") or "Unknown",
            "timezones": timezone.time_zones_for_number(parsed),
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
        })
    except Exception as e:
        result["error"] = str(e)
        return result
    telegram_result = {"telegram": "Not found"}
    try:
        clean_number = number.replace("+", "")
        search_url = f"https://t.me/s/{clean_number}"
        resp = requests.get(search_url, headers=get_headers(), timeout=6)
        if resp.status_code == 200 and "This channel doesn't exist" not in resp.text:
            telegram_result["telegram"] = "Possible public presence (check manually)"
        else:
            telegram_result["telegram"] = "No public Telegram link found"
    except Exception:
        telegram_result["telegram"] = "Check failed"
    result["telegram_check"] = telegram_result
    return result

def domain_lookup(domain):
    result = {"domain": domain}
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "registrar": w.registrar,
            "created": str(w.creation_date),
            "expires": str(w.expiration_date),
            "name_servers": w.name_servers,
            "registrant": w.name or w.org or "REDACTED",
            "emails": w.emails,
        }
    except Exception as e:
        result["whois_error"] = str(e)
    dns_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    result["dns"] = {}
    for rtype in dns_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            result["dns"][rtype] = [str(r) for r in answers]
        except:
            pass
    return result

def breach_check(target):
    if "@" not in target:
        return {"error": "Please enter an email address"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target)}?truncateResponse=true"
    headers = {"User-Agent": "OSINT-Tool"}
    try:
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            return {"breaches": [b["Name"] for b in r.json()]}
        if r.status_code == 404:
            return {"breaches": []}
        if r.status_code == 429:
            return {"error": "Rate limited – wait a minute"}
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def discord_basic(target):
    result = {"target": target}
    invite_code = target.strip()
    if "discord.gg/" in invite_code:
        invite_code = invite_code.split("discord.gg/")[-1]
    invite_code = invite_code.lstrip("/").strip()
    if len(invite_code) < 5 or not all(c.isalnum() for c in invite_code):
        result["status"] = "Invalid invite code format"
        result["note"] = "Limited to public invite data"
        return result
    url = f"https://discord.com/api/v9/invites/{invite_code}"
    data = fetch_json(url)
    if "error" in data:
        result["api_error"] = data["error"]
    elif "message" in data:
        result["api_message"] = data["message"]
        if data.get("code") == 10006:
            result["status"] = "Invite invalid, expired or revoked"
    elif "guild" in data:
        invite_data = {}
        invite_data["type"] = data.get("type")
        invite_data["code"] = data.get("code")
        if "inviter" in data:
            inv = data["inviter"]
            invite_data["inviter"] = {k: inv.get(k) for k in inv}
        if "expires_at" in data:
            invite_data["expires_at"] = data["expires_at"]
        if "guild" in data:
            g = data["guild"]
            invite_data["guild"] = {k: g.get(k) for k in g}
        if "channel" in data:
            ch = data["channel"]
            invite_data["channel"] = {k: ch.get(k) for k in ch}
        if "profile" in data:
            p = data["profile"]
            invite_data["profile"] = {k: p.get(k) for k in p}
        result["invite"] = invite_data
    else:
        result["status"] = "No guild information returned"
    result["note"] = "Limited to public invite data"
    return result

def username_check(username):
    sites = [
        ("X / Twitter", f"https://x.com/{username}"),
        ("Instagram", f"https://www.instagram.com/{username}/"),
        ("Facebook", f"https://www.facebook.com/{username}"),
        ("TikTok", f"https://www.tiktok.com/@{username}"),
        ("Snapchat", f"https://www.snapchat.com/add/{username}"),
        ("Pinterest", f"https://www.pinterest.com/{username}/"),
        ("LinkedIn", f"https://www.linkedin.com/in/{username}/"),
        ("Reddit", f"https://www.reddit.com/user/{username}"),
        ("Threads", f"https://www.threads.net/@{username}"),
        ("Bluesky", f"https://bsky.app/profile/{username}"),
        ("Mastodon", f"https://mastodon.social/@{username}"),
        ("GitHub", f"https://github.com/{username}"),
        ("GitLab", f"https://gitlab.com/{username}"),
        ("Bitbucket", f"https://bitbucket.org/{username}"),
        ("CodePen", f"https://codepen.io/{username}"),
        ("Replit", f"https://replit.com/@{username}"),
        ("HackerRank", f"https://www.hackerrank.com/{username}"),
        ("Twitch", f"https://www.twitch.tv/{username}"),
        ("Steam", f"https://steamcommunity.com/id/{username}/"),
        ("Roblox", f"https://www.roblox.com/user.aspx?username={username}"),
        ("Xbox", f"https://xboxgamertag.com/search/{username}"),
        ("PlayStation", f"https://psnprofiles.com/{username}"),
        ("YouTube", f"https://www.youtube.com/@{username}"),
        ("SoundCloud", f"https://soundcloud.com/{username}"),
        ("DeviantArt", f"https://www.deviantart.com/{username}"),
        ("Behance", f"https://www.behance.net/{username}"),
        ("Dribbble", f"https://dribbble.com/{username}"),
        ("ArtStation", f"https://www.artstation.com/{username}"),
        ("Quora", f"https://www.quora.com/profile/{username}"),
        ("Medium", f"https://medium.com/@{username}"),
        ("Tumblr", f"https://{username}.tumblr.com"),
        ("Disqus", f"https://disqus.com/by/{username}/"),
        ("Etsy", f"https://www.etsy.com/shop/{username}"),
        ("Fiverr", f"https://www.fiverr.com/{username}"),
        ("eBay", f"https://www.ebay.com/usr/{username}"),
        ("Keybase", f"https://keybase.io/{username}"),
        ("Gravatar", f"https://en.gravatar.com/{username}"),
        ("About.me", f"https://about.me/{username}"),
        ("Patreon", f"https://www.patreon.com/{username}"),
        ("DoxBin", f"https://doxbin.com/user/{username}")
    ]

    print(f"\nProfiles for username: {username}\n")

    for name, url in sites:
        print(f"{name}: {url}")


def instagram_lookup(username):
    result = {"username": username}
    try:
        L = instaloader.Instaloader()
        profile = instaloader.Profile.from_username(L.context, username)
        result.update({
            "full_name": profile.full_name or "Not set",
            "username": profile.username,
            "biography": profile.biography or "No bio",
            "followers": profile.followers,
            "following": profile.followees,
            "posts": profile.mediacount,
            "is_private": profile.is_private,
            "profile_pic_url": profile.profile_pic_url,
        })
    except:
        result["error"] = "Could not load profile (private, doesn't exist, rate limit, or login required)"
    return result

def tiktok_lookup(username):
    result = {"username": username}
    try:
        url = f"https://www.tiktok.com/@{username}"
        headers = get_headers()
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code != 200:
            result["error"] = f"Profile not found (HTTP {response.status_code})"
            return result
        start_str = '<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">'
        start_pos = response.text.find(start_str)
        if start_pos == -1:
            result["error"] = "Could not find profile data"
            return result
        start_pos += len(start_str)
        end_pos = response.text.find('</script>', start_pos)
        json_text = response.text[start_pos:end_pos].strip()
        if not json_text:
            result["error"] = "Empty data extracted"
            return result
        try:
            data = json.loads(json_text)
        except:
            result["error"] = "Invalid JSON in page data"
            return result
        default_scope = data.get("__DEFAULT_SCOPE__", {})
        user_detail = default_scope.get("webapp.user-detail", {}).get("userInfo", {})
        stats = user_detail.get("stats", {})
        if not user_detail:
            result["error"] = "No user info found in data"
            return result
        result.update({
            "nickname": user_detail.get("user", {}).get("nickname", "N/A"),
            "user_id": user_detail.get("user", {}).get("id", "N/A"),
            "verified": "Yes" if user_detail.get("user", {}).get("verified") else "No",
            "private_account": "Yes" if user_detail.get("user", {}).get("privateAccount") else "No",
            "bio": user_detail.get("user", {}).get("signature", "No bio"),
            "avatar_url": user_detail.get("user", {}).get("avatarLarger", "N/A"),
            "account_created": user_detail.get("user", {}).get("createTime", "N/A"),
            "stats": {
                "followers": f"{stats.get('followerCount', 'N/A'):,}",
                "following": f"{stats.get('followingCount', 'N/A'):,}",
                "hearts": f"{stats.get('heartCount', 'N/A'):,}",
                "videos": f"{stats.get('videoCount', 'N/A'):,}",
                "friends": f"{stats.get('friendCount', 'N/A'):,}",
            }
        })
    except Exception as e:
        result["error"] = f"Failed to fetch TikTok profile: {str(e)}"
    return result

def url_analysis(url):
    result = {"url": url}
    try:
        r = requests.head(url, timeout=6, allow_redirects=True)
        result["status"] = r.status_code
        result["final_url"] = str(r.url)
    except Exception as e:
        result["error"] = str(e)
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    if domain:
        result["domain_info"] = domain_lookup(domain)
    return result

def print_result(title, data):
    console.rule(f"[bold cyan]{title}[/bold cyan]")
    if "error" in data:
        console.print(f"[red]Error: {data['error']}[/red]")
        return
    table = Table(show_header=False, expand=True)
    table.add_column("Key", style="dim")
    table.add_column("Value")
    def add_rows(d, prefix=""):
        for k, v in d.items():
            key = prefix + k.replace("_", " ").title()
            if isinstance(v, dict):
                add_rows(v, key + ".")
            elif isinstance(v, list):
                table.add_row(key, json.dumps(v, indent=2, ensure_ascii=False))
            else:
                table.add_row(key, str(v))
    add_rows(data)
    console.print(table)

def menu():
    options = {
        "1": ("IP Geolocation", "Enter IP address", ip_lookup),
        "2": ("Phone Intelligence", "Enter phone number (e.g. +12025550123)", phone_lookup),
        "3": ("Domain Analysis", "Enter domain (e.g. example.com)", domain_lookup),
        "4": ("Breach Check", "Enter email address", breach_check),
        "5": ("Discord Invite Info", "Enter invite code", discord_basic),
        "6": ("Username Search", "Enter username", username_check),
        "7": ("Instagram Profile", "Enter Instagram username", instagram_lookup),
        "8": ("TikTok Profile", "Enter TikTok username (without @)", tiktok_lookup),
        "9": ("URL Analysis", "Enter full URL", url_analysis),
        "0": ("Exit", None, None),
    }
    while True:
        console.print("[bold green]OSINT Multi-Tool[/bold green]")
        for k, v in options.items():
            console.print(f"{k}: {v[0]}")
        choice = Prompt.ask("Choose an option", choices=list(options.keys()), default="0")
        if choice == "0":
            break
        if choice in options and options[choice][2]:
            prompt, func = options[choice][1], options[choice][2]
            target = Prompt.ask(prompt)
            res = func(target)
            print_result(options[choice][0], res)

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        sys.exit(0)

