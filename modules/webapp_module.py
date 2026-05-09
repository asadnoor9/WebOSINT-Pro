"""
WebOSINT Pro - Web App Structure Module
Robots.txt, sitemap, tech stack fingerprinting
"""

import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from core.base_module import BaseModule


TECH_SIGNATURES = {
    'WordPress': ['wp-content', 'wp-includes', 'WordPress'],
    'Joomla': ['joomla', '/components/com_'],
    'Drupal': ['drupal', '/sites/default/', 'Drupal.settings'],
    'Magento': ['Mage.Cookies', 'magento', '/skin/frontend/'],
    'Shopify': ['shopify', 'cdn.shopify.com', 'myshopify.com'],
    'PrestaShop': ['prestashop', '/modules/'],
    'Django': ['csrfmiddlewaretoken', 'django'],
    'Rails': ['rails', 'csrf-token', '_rails-'],
    'Laravel': ['laravel_session', 'XSRF-TOKEN'],
    'Angular': ['ng-version', 'angular', '__ng_'],
    'React': ['_react', '__REACT', 'data-reactroot'],
    'Vue.js': ['__vue', 'data-v-', 'vue.js'],
    'Next.js': ['__NEXT_DATA__', '_next/'],
    'Nuxt.js': ['__NUXT__', '_nuxt/'],
    'jQuery': ['jquery', 'jQuery'],
    'Bootstrap': ['bootstrap'],
    'Tailwind': ['tailwind'],
}


class Module(BaseModule):
    NAME = 'webapp'
    DESCRIPTION = 'Robots.txt, sitemap, tech fingerprinting'

    def run(self):
        results = {}
        base = f"https://{self.target}"

        # Robots.txt
        robots = self._parse_robots(base)
        results['robots_txt'] = robots

        # Sitemap
        sitemap_urls = robots.get('sitemaps', [])
        if not sitemap_urls:
            sitemap_urls = [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]

        sitemap_data = self._parse_sitemaps(sitemap_urls)
        results['sitemap'] = sitemap_data

        # Tech fingerprint from homepage
        tech = self._fingerprint_tech(base)
        results['technologies'] = tech

        # Meta info
        meta = self._extract_meta(base)
        results['meta'] = meta

        # Favicon hash (useful for Shodan searches)
        favicon = self._get_favicon_hash(base)
        results['favicon'] = favicon

        return results

    def _parse_robots(self, base):
        data = {'raw': '', 'disallowed': [], 'allowed': [], 'sitemaps': [], 'user_agents': []}
        try:
            r = self.get(f"{base}/robots.txt")
            if r and r.status_code == 200 and 'text' in r.headers.get('content-type', 'text'):
                data['raw'] = r.text
                current_ua = '*'
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith('user-agent:'):
                        current_ua = line.split(':', 1)[1].strip()
                        if current_ua not in data['user_agents']:
                            data['user_agents'].append(current_ua)
                    elif line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            data['disallowed'].append({'ua': current_ua, 'path': path})
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            data['allowed'].append({'ua': current_ua, 'path': path})
                    elif line.lower().startswith('sitemap:'):
                        url = line.split(':', 1)[1].strip()
                        if url:
                            data['sitemaps'].append(url)
        except Exception as e:
            self.log(f"Robots.txt error: {e}", 'debug')
        return data

    def _parse_sitemaps(self, sitemap_urls):
        all_urls = []
        processed = set()

        def fetch_sitemap(url):
            if url in processed:
                return
            processed.add(url)
            try:
                r = self.get(url)
                if not r or r.status_code != 200:
                    return
                root = ET.fromstring(r.content)
                ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

                # Sitemap index
                for sitemap in root.findall('sm:sitemap', ns):
                    loc = sitemap.find('sm:loc', ns)
                    if loc is not None and loc.text:
                        fetch_sitemap(loc.text.strip())

                # URLs
                for url_elem in root.findall('sm:url', ns):
                    loc = url_elem.find('sm:loc', ns)
                    if loc is not None and loc.text:
                        all_urls.append(loc.text.strip())
            except Exception as e:
                self.log(f"Sitemap parse error {url}: {e}", 'debug')

        for url in sitemap_urls[:5]:
            fetch_sitemap(url)

        return {
            'total_urls': len(all_urls),
            'urls': all_urls[:100],  # cap
        }

    def _fingerprint_tech(self, base):
        detected = []
        try:
            r = self.get(base, verify=False)
            if not r:
                return detected
            body = r.text
            headers_str = str(r.headers)

            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig in body or sig in headers_str:
                        detected.append(tech)
                        break
        except Exception as e:
            self.log(f"Tech fingerprint error: {e}", 'debug')
        return list(set(detected))

    def _extract_meta(self, base):
        meta = {}
        try:
            r = self.get(base, verify=False)
            if not r:
                return meta
            body = r.text

            # Generator
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
            if gen:
                meta['generator'] = gen.group(1)

            # Title
            title = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
            if title:
                meta['title'] = title.group(1).strip()

            # Description
            desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', body, re.I)
            if desc:
                meta['description'] = desc.group(1)[:200]

        except Exception as e:
            self.log(f"Meta extract error: {e}", 'debug')
        return meta

    def _get_favicon_hash(self, base):
        import hashlib
        try:
            r = self.get(f"{base}/favicon.ico", verify=False)
            if r and r.status_code == 200 and r.content:
                import mmh3, base64
                b64 = base64.encodebytes(r.content)
                fhash = mmh3.hash(b64)
                return {'hash': fhash, 'shodan_query': f'http.favicon.hash:{fhash}'}
        except ImportError:
            try:
                r = self.get(f"{base}/favicon.ico", verify=False)
                if r and r.content:
                    return {'md5': hashlib.md5(r.content).hexdigest()}
            except Exception:
                pass
        except Exception:
            pass
        return {}
