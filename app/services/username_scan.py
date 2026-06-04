import httpx
import asyncio
from typing import Dict, List, Optional
import re

# Platform definitions: name, URL template, detection method
PLATFORMS = [
    # Social Media
    {"name": "Twitter/X", "url": "https://twitter.com/{}", "category": "social"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "category": "social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "category": "social"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "category": "social"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "category": "professional"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "category": "social"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "category": "social"},
    # Developer
    {"name": "GitHub", "url": "https://github.com/{}", "category": "developer"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "category": "developer"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "category": "developer"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "category": "developer"},
    {"name": "Stack Overflow", "url": "https://stackoverflow.com/users/{}", "category": "developer"},
    # Media / Content
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "category": "media"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "category": "media"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "category": "media"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "category": "media"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "category": "media"},
    # Forums / Communities
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "category": "forum"},
    {"name": "Telegram", "url": "https://t.me/{}", "category": "messaging"},
    {"name": "Medium", "url": "https://medium.com/@{}", "category": "blog"},
    {"name": "Substack", "url": "https://substack.com/@{}", "category": "blog"},
    {"name": "WordPress", "url": "https://{}.wordpress.com", "category": "blog"},
    # Other
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "category": "other"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "category": "other"},
    {"name": "About.me", "url": "https://about.me/{}", "category": "other"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Patterns that indicate "not found" even on 200 responses
NOT_FOUND_PATTERNS = [
    "page not found", "user not found", "sorry, this page",
    "doesn't exist", "account suspended", "this account",
    "no results found", "404", "not available",
]


async def check_platform(
    session: httpx.AsyncClient,
    platform: Dict,
    username: str
) -> Dict:
    url = platform["url"].format(username)
    result = {
        "platform": platform["name"],
        "url": url,
        "category": platform["category"],
        "found": False,
        "status_code": None,
        "error": None,
    }

    try:
        resp = await session.get(url, timeout=8.0, follow_redirects=True)
        result["status_code"] = resp.status_code

        if resp.status_code == 200:
            # Check for "not found" patterns in response
            text_lower = resp.text[:3000].lower()
            is_not_found = any(p in text_lower for p in NOT_FOUND_PATTERNS)
            result["found"] = not is_not_found
        elif resp.status_code == 404:
            result["found"] = False
        elif resp.status_code in [301, 302]:
            result["found"] = False
        elif resp.status_code == 429:
            result["error"] = "Rate limited"
        else:
            result["found"] = False

    except httpx.TimeoutException:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)[:50]

    return result


async def scan_username(username: str) -> Dict:
    """Scan username across all platforms"""
    # Validate username
    username = username.strip().lstrip("@")
    if not re.match(r'^[a-zA-Z0-9._-]{1,50}$', username):
        return {
            "username": username,
            "error": "Invalid username format",
            "found_on": [],
            "not_found_on": [],
            "total_found": 0,
        }

    found_on = []
    not_found_on = []
    errors = []

    # Run in batches to avoid rate limiting
    async with httpx.AsyncClient(
        headers=HEADERS,
        follow_redirects=True,
        verify=False,
    ) as session:
        # Process in batches of 8
        batch_size = 8
        for i in range(0, len(PLATFORMS), batch_size):
            batch = PLATFORMS[i:i + batch_size]
            tasks = [check_platform(session, p, username) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    continue
                if result.get("error") and "Timeout" not in result["error"]:
                    errors.append(result)
                elif result.get("found"):
                    found_on.append(result)
                else:
                    not_found_on.append(result)

            # Small delay between batches
            if i + batch_size < len(PLATFORMS):
                await asyncio.sleep(0.5)

    return {
        "username": username,
        "total_found": len(found_on),
        "total_checked": len(PLATFORMS),
        "found_on": found_on,
        "not_found_on": not_found_on,
        "errors": errors,
        "platforms_by_category": _group_by_category(found_on),
    }


def _group_by_category(found: List[Dict]) -> Dict:
    groups: Dict[str, List] = {}
    for p in found:
        cat = p.get("category", "other")
        if cat not in groups:
            groups[cat] = []
        groups[cat].append(p["platform"])
    return groups


def analyze_username_threat(
    username: str,
    scan_result: Dict
) -> tuple:
    """
    Analyze if username presence pattern is suspicious.
    Returns (threat_score, confidence, reasons)
    """
    found_on = scan_result.get("found_on", [])
    total_found = len(found_on)
    reasons = []
    score = 0.0

    # Very high cross-platform presence can indicate coordinated persona
    if total_found >= 15:
        score += 30
        reasons.append(f"Extremely high cross-platform presence: {total_found} platforms — possible synthetic persona")
    elif total_found >= 10:
        score += 20
        reasons.append(f"High cross-platform presence: {total_found} platforms")
    elif total_found == 0:
        reasons.append("Username not found on any major platform")
        return 0.0, 0.3, reasons

    # Check for suspicious category combinations
    cats = scan_result.get("platforms_by_category", {})
    platform_names = [p["platform"] for p in found_on]

    # Bot-like: present on many forums but no professional presence
    has_professional = "professional" in cats
    has_social = "social" in cats
    has_developer = "developer" in cats

    if total_found >= 5 and not has_professional and not has_developer:
        score += 15
        reasons.append("No professional or developer profiles — primarily social/forum presence")

    # Check for suspicious username patterns
    if re.search(r'\d{4,}$', username):
        score += 10
        reasons.append(f"Username ends with numbers ({username}) — common bot pattern")

    if re.search(r'^(user|admin|bot|fake|test)\d*', username, re.IGNORECASE):
        score += 20
        reasons.append(f"Generic username prefix detected: '{username}'")

    # Calculate name consistency
    found_platforms = [p["platform"] for p in found_on]
    if total_found > 0:
        reasons.append(f"Found on {total_found} platform(s): {', '.join(found_platforms[:5])}")

    confidence = 0.6 if total_found > 3 else 0.4

    return min(score, 100), confidence, reasons
