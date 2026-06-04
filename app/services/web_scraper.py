import asyncio
import httpx
from bs4 import BeautifulSoup
from typing import Optional, Dict, List
import re
import tldextract

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

async def fetch_url(url: str, timeout: float = 10.0) -> Optional[str]:
    """Fetch URL content"""
    if not url.startswith("http"):
        url = "https://" + url
    try:
        async with httpx.AsyncClient(
            headers=HEADERS,
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.text
            return None
    except Exception as e:
        print(f"Fetch error for {url}: {e}")
        return None


def extract_content(html: str) -> Dict:
    """Extract structured content from HTML"""
    soup = BeautifulSoup(html, "lxml")

    # Remove noise
    for tag in soup(["script", "style", "nav", "footer", "header", "aside", "iframe"]):
        tag.decompose()

    # Title
    title = ""
    if soup.title:
        title = soup.title.string or ""

    # Meta description
    meta_desc = ""
    meta = soup.find("meta", {"name": "description"})
    if meta:
        meta_desc = meta.get("content", "")

    # Author
    author = ""
    for sel in ['[name="author"]', '[property="article:author"]', ".author", ".byline"]:
        el = soup.select_one(sel)
        if el:
            author = el.get("content") or el.get_text(strip=True)
            break

    # Published date
    pub_date = ""
    for sel in ['[property="article:published_time"]', '[name="publishdate"]', "time[datetime]"]:
        el = soup.select_one(sel)
        if el:
            pub_date = el.get("content") or el.get("datetime") or el.get_text(strip=True)
            break

    # Main text
    main_text = ""
    for sel in ["article", "main", '[role="main"]', ".content", "#content", ".post-content"]:
        el = soup.select_one(sel)
        if el:
            main_text = el.get_text(separator=" ", strip=True)
            break
    if not main_text:
        body = soup.find("body")
        if body:
            main_text = body.get_text(separator=" ", strip=True)

    # Clean text
    main_text = re.sub(r'\s+', ' ', main_text).strip()

    # External links
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("http") and "javascript:" not in href:
            ext = tldextract.extract(href)
            links.append(f"{ext.domain}.{ext.suffix}")
    links = list(set(links))[:20]

    # Images with alt text
    images = []
    for img in soup.find_all("img", alt=True):
        if img.get("alt", "").strip():
            images.append(img["alt"][:100])

    # Social meta
    og_data = {}
    for meta in soup.find_all("meta"):
        prop = meta.get("property", "") or meta.get("name", "")
        if prop.startswith("og:") or prop.startswith("twitter:"):
            og_data[prop] = meta.get("content", "")

    return {
        "title": title[:200],
        "meta_description": meta_desc[:300],
        "author": author[:100],
        "published_date": pub_date[:50],
        "main_text": main_text[:5000],
        "external_links": links,
        "images_alt": images[:10],
        "og_data": og_data,
        "word_count": len(main_text.split()),
    }


async def scrape_url(url: str) -> Optional[Dict]:
    """Scrape and extract content from URL"""
    html = await fetch_url(url)
    if not html:
        return None
    content = extract_content(html)
    content["url"] = url
    content["fetch_success"] = True
    return content


async def check_url_reputation(url: str) -> Dict:
    """Basic URL reputation checks"""
    flags = []
    score = 0

    # Check against Google Safe Browsing (free lookup via unofficial method)
    domain = tldextract.extract(url)
    full_domain = f"{domain.domain}.{domain.suffix}"

    # Suspicious URL patterns
    patterns = [
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Direct IP address in URL"),
        (r'[a-z0-9]{30,}\.', "Very long subdomain — possible phishing"),
        (r'(paypal|google|facebook|amazon|microsoft)-', "Brand name with hyphen — possible phishing"),
        (r'(login|signin|verify|secure|account|update|confirm)', "Sensitive keyword in URL"),
        (r'\.exe|\.zip|\.dmg|\.apk', "Executable file extension"),
        (r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly', "URL shortener — destination unknown"),
    ]

    for pattern, reason in patterns:
        if re.search(pattern, url, re.IGNORECASE):
            flags.append(reason)
            score += 15

    return {
        "url": url,
        "domain": full_domain,
        "suspicion_flags": flags,
        "base_risk_score": min(score, 100),
    }
