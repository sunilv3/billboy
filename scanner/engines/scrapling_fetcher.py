"""Scrapling-based stealth/adaptive fetcher for security scanning.

Wraps Scrapling's Fetcher and Selector for:
  - Stealth HTTP fetching with browser TLS fingerprint impersonation
  - Adaptive CSS/XPath element selection (survives site redesigns)
  - Deep endpoint discovery from HTML/JS content
  - Form and input extraction for injection testing
  - Anti-bot bypass via curl_cffi TLS fingerprint spoofing
"""
import re
import os
from urllib.parse import urljoin, urlparse
from core.logger import log
from core.utils import _find_tool, _safe_str

SCRAPLING_AVAILABLE = False
Fetcher = None
Selector = None

try:
    from scrapling.parser import Selector as _Selector
    from scrapling.fetchers import Fetcher as _Fetcher
    Fetcher = _Fetcher
    Selector = _Selector
    SCRAPLING_AVAILABLE = True
except ImportError:
    pass


def is_available():
    return SCRAPLING_AVAILABLE


def fetch_page(url, impersonate='chrome', timeout=15, stealthy_headers=True):
    """Fetch a page using Scrapling with browser TLS fingerprint impersonation.

    Returns dict with keys:
      - ok: bool
      - status: HTTP status code
      - text: response body text
      - selector: Scrapling Selector object (for CSS/XPath)
      - error: error message if failed
    """
    if not SCRAPLING_AVAILABLE:
        return {'ok': False, 'status': 0, 'text': '', 'selector': None, 'error': 'scrapling not installed'}

    try:
        page = Fetcher.get(
            url,
            stealthy_headers=stealthy_headers,
            timeout=timeout,
        )
        body = page.text if hasattr(page, 'text') else str(page.body if hasattr(page, 'body') else '')
        sel = Selector(content=body)
        return {
            'ok': True,
            'status': getattr(page, 'status', 200),
            'text': body,
            'selector': sel,
            'error': None,
        }
    except Exception as e:
        return {'ok': False, 'status': 0, 'text': '', 'selector': None, 'error': str(e)}


def extract_endpoints(url, base_url=None):
    """Fetch a page and extract all endpoints (URLs, forms, inputs, JS links).

    Returns dict with keys:
      - urls: list of absolute URLs found
      - forms: list of {action, method, inputs: [{name, type, value}]}
      - js_urls: list of URLs from script src attributes
      - links: list of href links
    """
    if not SCRAPLING_AVAILABLE:
        return {'urls': [], 'forms': [], 'js_urls': [], 'links': []}

    if not base_url:
        base_url = url

    result = fetch_page(url)
    if not result['ok'] or not result['selector']:
        return {'urls': [], 'forms': [], 'js_urls': [], 'links': []}

    sel = result['selector']
    urls = set()
    forms = []
    js_urls = []
    links = []

    # Extract all href links
    try:
        for tag in sel.css('a[href]'):
            href = tag.attrib.get('href', '') if hasattr(tag, 'attrib') else ''
            if href:
                abs_url = urljoin(base_url, href)
                urls.add(abs_url)
                links.append(abs_url)
    except Exception:
        pass

    # Extract script src URLs
    try:
        for tag in sel.css('script[src]'):
            src = tag.attrib.get('src', '') if hasattr(tag, 'attrib') else ''
            if src:
                abs_url = urljoin(base_url, src)
                urls.add(abs_url)
                js_urls.append(abs_url)
    except Exception:
        pass

    # Extract forms with inputs
    try:
        for form_tag in sel.css('form'):
            action = form_tag.attrib.get('action', '') if hasattr(form_tag, 'attrib') else ''
            method = form_tag.attrib.get('method', 'GET').upper()
            if action:
                action = urljoin(base_url, action)
                urls.add(action)

            inputs = []
            for inp in form_tag.css('input'):
                name = inp.attrib.get('name', '') if hasattr(inp, 'attrib') else ''
                inp_type = inp.attrib.get('type', 'text') if hasattr(inp, 'attrib') else 'text'
                value = inp.attrib.get('value', '') if hasattr(inp, 'attrib') else ''
                if name:
                    inputs.append({'name': name, 'type': inp_type, 'value': value})

            # Also extract select and textarea
            for sel_tag in form_tag.css('select'):
                name = sel_tag.attrib.get('name', '') if hasattr(sel_tag, 'attrib') else ''
                if name:
                    inputs.append({'name': name, 'type': 'select', 'value': ''})

            for ta in form_tag.css('textarea'):
                name = ta.attrib.get('name', '') if hasattr(ta, 'attrib') else ''
                if name:
                    inputs.append({'name': name, 'type': 'textarea', 'value': ''})

            forms.append({'action': action, 'method': method, 'inputs': inputs})
    except Exception:
        pass

    # Extract meta refresh and redirect URLs
    try:
        for meta in sel.css('meta[http-equiv="refresh"]'):
            content = meta.attrib.get('content', '') if hasattr(meta, 'attrib') else ''
            match = re.search(r'url=(.+)', content, re.IGNORECASE)
            if match:
                redirect_url = urljoin(base_url, match.group(1).strip())
                urls.add(redirect_url)
    except Exception:
        pass

    return {
        'urls': list(urls),
        'forms': forms,
        'js_urls': js_urls,
        'links': links,
    }


def extract_forms_with_details(url):
    """Fetch a page and extract all forms with full input details for injection testing.

    Returns list of dicts:
      - action: form action URL
      - method: GET or POST
      - enctype: encoding type
      - inputs: [{name, type, value, placeholder, required}]
      - hidden_inputs: [{name, value}] (for CSRF tokens etc.)
    """
    if not SCRAPLING_AVAILABLE:
        return []

    result = fetch_page(url)
    if not result['ok'] or not result['selector']:
        return []

    sel = result['selector']
    forms = []

    try:
        for form_tag in sel.css('form'):
            action = form_tag.attrib.get('action', '') if hasattr(form_tag, 'attrib') else ''
            method = form_tag.attrib.get('method', 'GET').upper()
            enctype = form_tag.attrib.get('enctype', '') if hasattr(form_tag, 'attrib') else ''
            if action:
                action = urljoin(url, action)

            inputs = []
            hidden_inputs = []

            for inp in form_tag.css('input'):
                attrs = inp.attrib if hasattr(inp, 'attrib') else {}
                name = attrs.get('name', '')
                inp_type = attrs.get('type', 'text')
                value = attrs.get('value', '')
                placeholder = attrs.get('placeholder', '')
                required = attrs.get('required', '') != ''

                if not name:
                    continue

                info = {
                    'name': name,
                    'type': inp_type,
                    'value': value,
                    'placeholder': placeholder,
                    'required': required,
                }

                if inp_type == 'hidden':
                    hidden_inputs.append({'name': name, 'value': value})
                else:
                    inputs.append(info)

            # Also extract select and textarea
            for sel_tag in form_tag.css('select'):
                name = sel_tag.attrib.get('name', '') if hasattr(sel_tag, 'attrib') else ''
                if name:
                    inputs.append({'name': name, 'type': 'select', 'value': '', 'placeholder': '', 'required': False})

            for ta in form_tag.css('textarea'):
                name = ta.attrib.get('name', '') if hasattr(ta, 'attrib') else ''
                if name:
                    inputs.append({'name': name, 'type': 'textarea', 'value': '', 'placeholder': '', 'required': False})

            forms.append({
                'action': action,
                'method': method,
                'enctype': enctype,
                'inputs': inputs,
                'hidden_inputs': hidden_inputs,
            })
    except Exception:
        pass

    return forms


def parse_html(html_content):
    """Parse raw HTML content using Scrapling Selector.

    Returns a Selector object for CSS/XPath queries.
    """
    if not SCRAPLING_AVAILABLE:
        return None

    try:
        return Selector(content=html_content)
    except Exception:
        return None


def css_select(selector_or_html, css_query):
    """Run a CSS query on a Selector or raw HTML string.

    Returns list of dicts with keys: tag, text, attribs, html
    """
    if isinstance(selector_or_html, str):
        sel = parse_html(selector_or_html)
    else:
        sel = selector_or_html

    if not sel:
        return []

    results = []
    try:
        for el in sel.css(css_query):
            info = {
                'tag': el.tag if hasattr(el, 'tag') else '',
                'text': el.text if hasattr(el, 'text') else '',
                'attribs': el.attrib if hasattr(el, 'attrib') else {},
                'html': el.html if hasattr(el, 'html') else '',
            }
            results.append(info)
    except Exception:
        pass

    return results


def xpath_select(selector_or_html, xpath_query):
    """Run an XPath query on a Selector or raw HTML string.

    Returns list of dicts with keys: tag, text, attribs, html
    """
    if isinstance(selector_or_html, str):
        sel = parse_html(selector_or_html)
    else:
        sel = selector_or_html

    if not sel:
        return []

    results = []
    try:
        for el in sel.xpath(xpath_query):
            info = {
                'tag': el.tag if hasattr(el, 'tag') else '',
                'text': el.text if hasattr(el, 'text') else '',
                'attribs': el.attrib if hasattr(el, 'attrib') else {},
                'html': el.html if hasattr(el, 'html') else '',
            }
            results.append(info)
    except Exception:
        pass

    return results
