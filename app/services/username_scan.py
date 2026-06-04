import httpx
import asyncio
from typing import Dict, List, Optional
import re

# Platforms with verification method:
# - "api": has public API for verification
# - "meta": check og:title or meta tags
# - "content": check page content for username/name
# - "status": 404 = not found (reliable)
PLATFORMS = [
    # High confidence - API or reliable 404
    {"name": "GitHub", "url": "https://api.github.com/users/{}", "category": "developer", "method": "api", "api_field": "login"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}/about.json", "category": "forum", "method": "api", "api_field": "name"},
    {"name": "Twitter/X", "url": "https://twitter.com/{}", "category": "social", "method": "status"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "category": "social", "method": "status"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "category": "social", "method": "status"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "category": "professional", "method": "status"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "category": "media", "method": "content", "not_found_text": "This page isn't available"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "category": "media", "method": "content", "not_found_text": "Sorry. Unless you've got a time machine"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "category": "social", "method": "content", "not_found_text": "Hmm, we couldn't find that page"},
    {"name": "Telegram", "url": "https://t.me/{}", "category": "messaging", "method": "content", "found_text": "View in Telegram"},
    {"name": "Medium", "url": "https://medium.com/@{}", "category": "blog", "method": "content", "not_found_text": "Page not found"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "category": "developer", "method": "content", "not_found_text": "Page Not Found"},
    {"name": "Substack", "url": "https://substack.com/@{}", "category": "blog", "method": "content", "not_found_text": "not found"},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "category": "other", "method": "content", "not_found_text": "Sorry, we couldn't find"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "category": "other", "method": "content", "not_found_text": "Sorry, this page isn't available"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "category": "media", "method": "content", "not_found_text": "We can't find this user"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "category": "media", "method": "content", "not_found_text": "Page not found"},
    {"name": "HackerNews", "url": "https://hacker-news.firebaseio.com/v0/user/{}.json", "category": "developer", "method": "api_notnull"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "category": "social", "method": "content", "found_text": "Add me on Snapchat"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "category": "social", "method": "status"},
    {"name": "About.me", "url": "https://about.me/{}", "category": "other", "method": "content", "not_found_text": "page doesn't exist"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "category": "media", "method": "content", "not_found_text": "Page not found"},
    {"name": "WordPress", "url": "https://{}.wordpress.com", "category": "blog", "method": "content", "not_found_text": "doesn't exist"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "category": "developer", "method": "content", "not_found_text": "Page Not Found"},
    {"name": "Mastodon", "url": "https://mastodon.social/@{}", "category": "social", "method": "content", "not_found_text": "This profile is not available"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

API_HEADERS = {
    "User-Agent": "ATIP-Scanner/1.0",
    "Accept": "application/json",
}


async def check_platform(session: httpx.AsyncClient, platform: Dict, username: str) -> Dict:
    url = platform["url"].format(username)
    method = platform.get("method", "status")

    result = {
        "platform": platform["name"],
        "url": platform["url"].format(username) if method != "api" else f"https://{platform['name'].lower().replace('/', '').replace(' ', '')}.com/{username}",
        "category": platform["category"],
        "found": False,
        "confidence": "low",
        "status_code": None,
        "error": None,
    }

    try:
        headers = API_HEADERS if method in ("api", "api_notnull") else HEADERS

        resp = await session.get(url, timeout=8.0, follow_redirects=True, headers=headers)
        result["status_code"] = resp.status_code

        if method == "api":
            # GitHub, Reddit — check if API returns valid user object
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    field = platform.get("api_field", "id")
                    if data.get(field):
                        result["found"] = True
                        result["confidence"] = "high"
                        # Use real profile URL
                        if platform["name"] == "GitHub":
                            result["url"] = f"https://github.com/{username}"
                        elif platform["name"] == "Reddit":
                            result["url"] = f"https://reddit.com/u/{username}"
                except Exception:
                    result["found"] = False
            elif resp.status_code == 404:
                result["found"] = False

        elif method == "api_notnull":
            # HackerNews - returns null if not found
            if resp.status_code == 200:
                text = resp.text.strip()
                result["found"] = text != "null" and len(text) > 10
                result["confidence"] = "high" if result["found"] else "low"
                result["url"] = f"https://news.ycombinator.com/user?id={username}"

        elif method == "status":
            # Reliable 404 detection
            if resp.status_code == 200:
                result["found"] = True
                result["confidence"] = "medium"
            elif resp.status_code == 404:
                result["found"] = False

        elif method == "content":
            if resp.status_code == 404:
                result["found"] = False
            elif resp.status_code == 200:
                text_lower = resp.text[:5000].lower()

                # Check for explicit "not found" text
                not_found = platform.get("not_found_text", "")
                found_text = platform.get("found_text", "")

                if not_found and not_found.lower() in text_lower:
                    result["found"] = False
                elif found_text and found_text.lower() in text_lower:
                    result["found"] = True
                    result["confidence"] = "medium"
                elif not_found:
                    # If not_found_text defined and NOT in page → likely found
                    result["found"] = True
                    result["confidence"] = "low"
                else:
                    result["found"] = False

    except httpx.TimeoutException:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:40]

    return result


async def scan_username(username: str) -> Dict:
    username = username.strip().lstrip("@")
    if not re.match(r'^[a-zA-Z0-9._-]{1,50}$', username):
        return {"username": username, "error": "Invalid username format", "found_on": [], "not_found_on": [], "total_found": 0}

    found_on = []
    not_found_on = []

    async with httpx.AsyncClient(
        headers=HEADERS, follow_redirects=True, verify=False,
    ) as session:
        batch_size = 6
        for i in range(0, len(PLATFORMS), batch_size):
            batch = PLATFORMS[i:i + batch_size]
            tasks = [check_platform(session, p, username) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    continue
                if result.get("found"):
                    found_on.append(result)
                else:
                    not_found_on.append(result)
            if i + batch_size < len(PLATFORMS):
                await asyncio.sleep(0.3)

    # Separate by confidence
    high_conf = [p for p in found_on if p.get("confidence") == "high"]
    med_conf = [p for p in found_on if p.get("confidence") == "medium"]
    low_conf = [p for p in found_on if p.get("confidence") == "low"]

    return {
        "username": username,
        "total_found": len(found_on),
        "total_checked": len(PLATFORMS),
        "high_confidence_count": len(high_conf),
        "found_on": found_on,
        "not_found_on": not_found_on,
        "platforms_by_category": _group_by_category(found_on),
        "confidence_breakdown": {
            "high": [p["platform"] for p in high_conf],
            "medium": [p["platform"] for p in med_conf],
            "low": [p["platform"] for p in low_conf],
        }
    }


def _group_by_category(found: List[Dict]) -> Dict:
    groups: Dict[str, List] = {}
    for p in found:
        cat = p.get("category", "other")
        if cat not in groups:
            groups[cat] = []
        groups[cat].append(p["platform"])
    return groups


def analyze_username_threat(username: str, scan_result: Dict) -> tuple:
    found_on = scan_result.get("found_on", [])
    total_found = len(found_on)
    high_conf = scan_result.get("high_confidence_count", 0)
    reasons = []
    score = 0.0

    if total_found == 0:
        reasons.append("Username not found on any major platform")
        return 0.0, 0.3, reasons

    if total_found >= 15:
        score += 25
        reasons.append(f"Very high cross-platform spread: {total_found} platforms")
    elif total_found >= 8:
        score += 10

    if high_conf >= 3:
        reasons.append(f"Verified on {high_conf} platforms (GitHub, Reddit, HackerNews)")

    # Suspicious patterns
    if re.search(r'\d{4,}$', username):
        score += 15
        reasons.append(f"Numeric suffix pattern — common in bot usernames")
    if re.search(r'^(user|admin|bot|fake|test|real)', username, re.IGNORECASE):
        score += 20
        reasons.append(f"Generic prefix detected")

    platform_names = [p["platform"] for p in found_on if p.get("confidence") in ("high", "medium")]
    if platform_names:
        reasons.append(f"Confirmed on: {', '.join(platform_names[:6])}")
    elif found_on:
        reasons.append(f"Found (low confidence) on: {', '.join([p['platform'] for p in found_on[:5]])}")

    confidence = 0.7 if high_conf > 0 else 0.45

    return min(score, 100), confidence, reasons
