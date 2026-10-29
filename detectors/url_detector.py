import re
import urllib.parse
import ipaddress

class URLPhishingDetector:
    """
    Advanced Heuristic and Pattern-Based Phishing URL Detection Engine
    Evaluates lexical, structural, protocol, and brand-spoofing characteristics.
    Produces an explainable risk score (0-100) and actionable safety advice.
    """

    KNOWN_BRANDS = {
        'paypal': ['paypal.com', 'paypal.me'],
        'google': ['google.com', 'google.co', 'google.org', 'gmail.com'],
        'apple': ['apple.com', 'icloud.com'],
        'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'],
        'netflix': ['netflix.com'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'aws.amazon.com'],
        'facebook': ['facebook.com', 'fb.com', 'meta.com'],
        'instagram': ['instagram.com'],
        'chase': ['chase.com'],
        'wellsfargo': ['wellsfargo.com'],
        'bankofamerica': ['bankofamerica.com'],
        'binance': ['binance.com'],
        'coinbase': ['coinbase.com'],
        'dropbox': ['dropbox.com'],
        'adobe': ['adobe.com'],
        'linkedin': ['linkedin.com'],
        'twitter': ['twitter.com', 'x.com'],
        'steam': ['steampowered.com', 'steamcommunity.com'],
        'spotify': ['spotify.com']
    }

    SUSPICIOUS_TLDS = {
        'xyz', 'top', 'work', 'club', 'tk', 'ga', 'cf', 'gq', 'ml', 'ru',
        'buzz', 'surf', 'click', 'live', 'support', 'shop', 'link', 'icu',
        'cam', 'stream', 'fit', 'monster', 'rest', 'bar', 'country', 'kim'
    }

    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
        'rebrand.ly', 'cutt.ly', 'goo.gl', 'shorturl.at', 'rb.gy', 'v.gd'
    }

    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'verification', 'secure', 'banking', 'account',
        'signin', 'sign-in', 'password', 'recover', 'suspended', 'wallet',
        'auth', 'authenticate', 'confirm', 'update', 'billing', 'validate',
        'ebayisapi', 'webscr', 'security', 'alert', 'identity', 'unlock'
    ]

    def __init__(self):
        pass

    def analyze(self, raw_url):
        raw_url = raw_url.strip() if raw_url else ''
        if not raw_url:
            return self._empty_result("Empty URL provided")

        # Normalize URL scheme if missing for parsing
        normalized_url = raw_url
        if not re.match(r'^[a-zA-Z]+://', raw_url):
            normalized_url = 'http://' + raw_url

        try:
            parsed = urllib.parse.urlparse(normalized_url)
        except Exception as e:
            return self._empty_result(f"Invalid URL structure: {str(e)}")

        hostname = parsed.hostname or ''
        netloc = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        full_path = path + ('?' + query if query else '')

        indicators = []
        passed_checks = []
        potential_concerns = []
        risk_score = 0

        # 1. IP Address Detection
        is_ip = self._check_ip_address(hostname)
        if is_ip:
            risk_score += 40
            concern = {
                'id': 'ip_address',
                'name': 'Raw IP Address as Hostname',
                'severity': 'high',
                'status': 'danger',
                'icon': 'alert-circle',
                'value': hostname,
                'description': f'Hostname is an IP address ({hostname}) rather than a registered domain name.',
                'rationale': 'Legitimate organizations use registered domain names. Attackers often deploy malicious phishing landing pages on bare IP addresses to evade domain registry screening.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        else:
            passed = {
                'id': 'no_ip',
                'name': 'Standard Domain Name Format',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': 'Target uses standard domain name resolution rather than a raw IP address.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 2. HTTPS / Protocol Security
        has_https = parsed.scheme.lower() == 'https'
        if has_https:
            risk_score -= 10
            passed = {
                'id': 'https_enabled',
                'name': 'HTTPS Protocol Enabled',
                'status': 'pass',
                'icon': 'shield-check',
                'description': 'The URL employs Transport Layer Security (TLS/HTTPS) for communication encryption.'
            }
            passed_checks.append(passed)
            indicators.append(passed)
        else:
            risk_score += 20
            concern = {
                'id': 'insecure_http',
                'name': 'Insecure HTTP Protocol',
                'severity': 'medium',
                'status': 'warning',
                'icon': 'unlock',
                'value': parsed.scheme.upper(),
                'description': 'Traffic transmitted over plain HTTP is unencrypted and vulnerable to interception.',
                'rationale': 'Legitimate financial and login portals universally mandate HTTPS. Plain HTTP creates man-in-the-middle risks.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)

        # 3. URL Length Analysis
        url_len = len(raw_url)
        if url_len > 100:
            risk_score += 25
            concern = {
                'id': 'url_length_excessive',
                'name': 'Excessively Long URL',
                'severity': 'high',
                'status': 'danger',
                'icon': 'maximize-2',
                'value': f'{url_len} characters',
                'description': f'The URL is unusually long ({url_len} characters).',
                'rationale': 'Phishers intentionally construct verbose, convoluted URLs to bury suspicious subdomain redirects and bypass browser address bar visibility.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        elif url_len > 75:
            risk_score += 12
            concern = {
                'id': 'url_length_elevated',
                'name': 'Elevated URL Length',
                'severity': 'medium',
                'status': 'warning',
                'icon': 'maximize',
                'value': f'{url_len} characters',
                'description': f'The URL length ({url_len} chars) is higher than normal web endpoints.',
                'rationale': 'Extended length can be used to obfuscate tracking tokens or unauthorized redirects.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        else:
            passed = {
                'id': 'url_length_normal',
                'name': 'Normal URL Length',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': f'URL length ({url_len} characters) is within typical standard bounds.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 4. Brand Impersonation & Typosquatting
        brand_spoof = self._check_brand_spoofing(hostname)
        if brand_spoof:
            risk_score += 45
            concern = {
                'id': 'brand_spoofing',
                'name': 'Targeted Brand Spoofing / Impersonation',
                'severity': 'critical',
                'status': 'danger',
                'icon': 'alert-triangle',
                'value': brand_spoof['brand'],
                'description': f'The domain contains the brand name "{brand_spoof["brand"]}" but is not an official {brand_spoof["brand"]} domain.',
                'rationale': f'Attackers register misleading domains containing well-known brands ({brand_spoof["brand"]}) to trick victims into trusting a fake login portal.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        else:
            passed = {
                'id': 'no_brand_spoof',
                'name': 'No Known Brand Impersonation',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': 'No unauthorized misuse of monitored brand trademarks detected in hostname.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 5. Subdomain Count Analysis
        domain_parts = [p for p in hostname.split('.') if p]
        subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) > 1 else 0
        if subdomain_count >= 3:
            risk_score += 25
            concern = {
                'id': 'excessive_subdomains',
                'name': 'Multiple Subdomain Layers',
                'severity': 'high',
                'status': 'danger',
                'icon': 'layers',
                'value': f'{subdomain_count} subdomains',
                'description': f'Detected {subdomain_count} nested subdomain levels ({hostname}).',
                'rationale': 'Phishing kits frequently string multiple subdomains together (e.g., paypal.com.account-update.badsite.com) so mobile browsers display only the trusted brand name.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        elif subdomain_count == 2:
            risk_score += 10
            concern = {
                'id': 'moderate_subdomains',
                'name': 'Multiple Subdomains Detected',
                'severity': 'low',
                'status': 'warning',
                'icon': 'layers',
                'value': f'{subdomain_count} subdomains',
                'description': f'{subdomain_count} subdomains detected.',
                'rationale': 'Slightly elevated structure, common in both complex enterprise networks and staged phishing pages.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        else:
            passed = {
                'id': 'normal_subdomains',
                'name': 'Standard Domain Hierarchy',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': 'Domain structure exhibits standard, clean root/subdomain hierarchy.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 6. At-Symbol (@) Check
        if '@' in raw_url:
            risk_score += 35
            concern = {
                'id': 'at_symbol',
                'name': '@ Symbol Embedded in URL',
                'severity': 'critical',
                'status': 'danger',
                'icon': 'at-sign',
                'value': '@ detected',
                'description': 'URL contains an "@" symbol.',
                'rationale': 'In URI syntax, anything preceding the "@" symbol represents user credentials and is ignored by the browser, causing the browser to route to the host immediately following "@".'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        else:
            passed = {
                'id': 'no_at_symbol',
                'name': 'No Embedded Credential Routing (@)',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': 'No URL obfuscation via credentials delimiter (@) detected.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 7. Double Slash (//) in Path Redirection
        if '//' in path:
            risk_score += 30
            concern = {
                'id': 'double_slash_path',
                'name': 'Double Slash Redirect Bypass in Path',
                'severity': 'high',
                'status': 'danger',
                'icon': 'corner-down-right',
                'value': '// in path',
                'description': 'URL path contains unexpected double slashes "//".',
                'rationale': 'Often utilized in open-redirect exploits where legitimate domains are abused to forward victims to malicious destinations.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)

        # 8. Hyphen in Domain Name
        if '-' in hostname:
            hyphen_count = hostname.count('-')
            score_add = 20 if hyphen_count > 1 else 10
            risk_score += score_add
            concern = {
                'id': 'domain_hyphen',
                'name': 'Hyphenated Domain Name',
                'severity': 'medium',
                'status': 'warning',
                'icon': 'minus',
                'value': f'{hyphen_count} hyphen(s)',
                'description': f'Hostname contains {hyphen_count} hyphen character(s).',
                'rationale': 'Attackers frequently combine legitimate company names with keywords using hyphens (e.g. apple-support-login.com).'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        else:
            passed = {
                'id': 'no_hyphen',
                'name': 'No Domain Hyphen Splitting',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': 'Hostname does not rely on synthetic hyphenation strings.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 9. Suspicious Keywords in Domain/Path
        matched_keywords = []
        lowered_full = (hostname + full_path).lower()
        for kw in self.SUSPICIOUS_KEYWORDS:
            if kw in lowered_full:
                matched_keywords.append(kw)

        if matched_keywords:
            kw_score = min(35, len(matched_keywords) * 10)
            risk_score += kw_score
            concern = {
                'id': 'suspicious_keywords',
                'name': 'Security & Authentication Keywords Detected',
                'severity': 'high' if len(matched_keywords) > 2 else 'medium',
                'status': 'danger' if len(matched_keywords) > 2 else 'warning',
                'icon': 'key',
                'value': ', '.join(matched_keywords[:4]),
                'description': f'URL contains high-value lure keywords: {", ".join(matched_keywords[:5])}.',
                'rationale': 'Phishing lures frequently mimic authentication terminology (e.g. login, verify, secure, banking) to elicit user action.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        else:
            passed = {
                'id': 'no_suspicious_keywords',
                'name': 'No Phishing Bait Keywords',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': 'No typical credential harvesting or account verification keywords identified.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 10. URL Shortener Service
        if hostname.lower() in self.URL_SHORTENERS:
            risk_score += 25
            concern = {
                'id': 'url_shortener',
                'name': 'URL Shortener Service Used',
                'severity': 'medium',
                'status': 'warning',
                'icon': 'external-link',
                'value': hostname,
                'description': f'The domain "{hostname}" is a URL redirection/shortening service.',
                'rationale': 'Shorteners mask the final target endpoint, preventing preview analysis and bypassing automated inspection filters.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)

        # 11. High-Risk / Disposable TLD
        tld = hostname.split('.')[-1].lower() if '.' in hostname else ''
        if tld in self.SUSPICIOUS_TLDS:
            risk_score += 25
            concern = {
                'id': 'suspicious_tld',
                'name': 'High-Risk Top Level Domain (TLD)',
                'severity': 'high',
                'status': 'warning',
                'icon': 'globe',
                'value': f'.{tld}',
                'description': f'The .{tld} extension has a statistically elevated association with cyber threats and spam.',
                'rationale': 'Certain cheap or free TLD registries are preferred by attackers due to minimal identity verification and disposable lifecycles.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)
        elif tld in {'com', 'org', 'edu', 'gov', 'net', 'io'}:
            passed = {
                'id': 'standard_tld',
                'name': 'Standard Top Level Domain (TLD)',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': f'The .{tld} registry is an established standard domain namespace.'
            }
            passed_checks.append(passed)
            indicators.append(passed)

        # 12. Non-standard Port
        if parsed.port and parsed.port not in [80, 443]:
            risk_score += 20
            concern = {
                'id': 'non_standard_port',
                'name': 'Non-Standard Web Port',
                'severity': 'medium',
                'status': 'warning',
                'icon': 'radio',
                'value': f':{parsed.port}',
                'description': f'URL routes through custom port :{parsed.port} rather than standard HTTP(80)/HTTPS(443).',
                'rationale': 'Legitimate enterprise portals rarely run customer-facing login services on non-standard network ports.'
            }
            indicators.append(concern)
            potential_concerns.append(concern)

        # 13. Hex / Percent Encoding Obfuscation
        if '%' in raw_url:
            encoded_matches = re.findall(r'%[0-9a-fA-F]{2}', raw_url)
            if len(encoded_matches) > 3:
                risk_score += 20
                concern = {
                    'id': 'hex_obfuscation',
                    'name': 'Hexadecimal / Percent Obfuscation',
                    'severity': 'medium',
                    'status': 'warning',
                    'icon': 'code',
                    'value': f'{len(encoded_matches)} escaped sequences',
                    'description': 'URL contains multiple percent-encoded hex sequences.',
                    'rationale': 'Obfuscated character sequences are often used to conceal target keywords or script injection payloads from inspection engines.'
                }
                indicators.append(concern)
                potential_concerns.append(concern)

        # 14. Punycode / Internationalized Homograph Attack
        if 'xn--' in hostname.lower():
            risk_score += 40
            concern = {
                'id': 'punycode_homograph',
                'name': 'Punycode / Homograph Attack Detected',
                'severity': 'critical',
                'status': 'danger',
                'icon': 'alert-octagon',
                'value': hostname,
                'description': 'Hostname utilizes Punycode ("xn--") encoding.',
                'rationale': 'Attackers use visual Cyrillic or Greek lookalike characters (homoglyphs) to forge identical-looking URLs (e.g. swapping latin "a" with cyrillic "а").'
            }
            indicators.append(concern)
            potential_concerns.append(concern)

        # Cap score between 0 and 100
        risk_score = max(5, min(99, risk_score))

        # Risk Classification
        if risk_score >= 70:
            risk_level = 'PHISHING LIKELY'
            risk_badge = 'danger'
            recommendation = (
                "CRITICAL WARNING: This URL displays multiple high-confidence phishing indicators. "
                "Do NOT enter passwords, banking details, or download any files. "
                "If received via email or message, delete it and report it to your cybersecurity officer."
            )
        elif risk_score >= 35:
            risk_level = 'SUSPICIOUS'
            risk_badge = 'warning'
            recommendation = (
                "CAUTION ADVISED: This URL displays several anomalous patterns (such as unusual subdomains, "
                "keywords, or masking). Avoid submitting personal or financial information without "
                "verifying the sender via an independent trusted channel."
            )
        else:
            risk_level = 'LOW RISK'
            risk_badge = 'success'
            recommendation = (
                "SAFE TO PROCEED: This link matches expected legitimate structural standards with HTTPS "
                "encryption and no obvious brand-impersonation indicators. Always maintain standard digital hygiene."
            )

        return {
            'url': raw_url,
            'normalized_url': normalized_url,
            'hostname': hostname,
            'domain': hostname,
            'scheme': parsed.scheme.upper(),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_badge': risk_badge,
            'passed_checks': passed_checks,
            'potential_concerns': potential_concerns,
            'indicators': indicators,
            'passed_count': len(passed_checks),
            'concern_count': len(potential_concerns),
            'recommendation': recommendation
        }

    def _check_ip_address(self, hostname):
        if not hostname:
            return False
        # Remove brackets for IPv6 if present
        cleaned = hostname.strip('[]')
        try:
            ipaddress.ip_address(cleaned)
            return True
        except ValueError:
            return False

    def _check_brand_spoofing(self, hostname):
        lower_host = hostname.lower()
        for brand, legitimate_domains in self.KNOWN_BRANDS.items():
            if brand in lower_host:
                # Check if it actually matches one of the legitimate domains
                matches_legit = False
                for legit in legitimate_domains:
                    if lower_host == legit or lower_host.endswith('.' + legit):
                        matches_legit = True
                        break
                if not matches_legit:
                    return {'brand': brand.capitalize(), 'detected_in': hostname}
        return None

    def _empty_result(self, error_msg):
        return {
            'url': '',
            'hostname': 'N/A',
            'domain': 'N/A',
            'scheme': 'NONE',
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'risk_badge': 'neutral',
            'passed_checks': [],
            'potential_concerns': [{
                'id': 'error',
                'name': 'Input Error',
                'severity': 'info',
                'status': 'warning',
                'icon': 'alert-circle',
                'description': error_msg,
                'rationale': 'Ensure a valid web address is supplied.'
            }],
            'indicators': [],
            'passed_count': 0,
            'concern_count': 1,
            'recommendation': 'Please input a valid URL string to initiate security telemetry.'
        }
