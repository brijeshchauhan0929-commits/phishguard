import re
from .url_detector import URLPhishingDetector

class EmailThreatDetector:
    """
    Advanced Heuristic Email Phishing and Social Engineering Detector.
    Scans sender spoofing, psychological urgency triggers, credential harvesting lures,
    financial extortion, generic greetings, and embedded malicious links.
    """

    TRUSTED_ORGANIZATIONS = {
        'paypal': ['paypal.com', 'service.paypal.com'],
        'google': ['google.com', 'accounts.google.com'],
        'microsoft': ['microsoft.com', 'accountprotection.microsoft.com', 'microsoftonline.com'],
        'apple': ['apple.com', 'id.apple.com'],
        'amazon': ['amazon.com', 'orders.amazon.com'],
        'netflix': ['netflix.com', 'mailer.netflix.com'],
        'bank of america': ['bankofamerica.com'],
        'chase': ['chase.com'],
        'wells fargo': ['wellsfargo.com']
    }

    FREE_EMAIL_PROVIDERS = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'aol.com', 'icloud.com', 'protonmail.com', 'zoho.com', 'mail.com'
    }

    URGENCY_PATTERNS = [
        r'\b(?:urgent|immediately|immediate action|critical alert)\b',
        r'\b(?:account suspended|account locked|temporarily disabled|profile restricted)\b',
        r'\b(?:within \d+ hours?|within 24 hours|within 48 hours|final warning|last notice)\b',
        r'\b(?:unauthorized login|unrecognized device|security breach|suspicious activity)\b',
        r'\b(?:act now|time sensitive|deadline expiring|action required)\b'
    ]

    CREDENTIAL_PATTERNS = [
        r'\b(?:verify your password|enter your credentials|confirm your password|reset password)\b',
        r'\b(?:social security|ssn|tax id|national id)\b',
        r'\b(?:credit card|debit card|cvv|card expiration|pin number)\b',
        r'\b(?:bank account number|routing number|wire transfer)\b',
        r'\b(?:crypto wallet|seed phrase|recovery phrase|private key)\b'
    ]

    FINANCIAL_SCAM_PATTERNS = [
        r'\b(?:gift card|itunes card|steam card|google play card)\b',
        r'\b(?:lottery winner|inherited fortune|cryptocurrency investment|guaranteed return)\b',
        r'\b(?:invoice attached|unpaid invoice|overdue payment|wire the funds)\b',
        r'\b(?:western union|moneygram|cashapp|venmo transaction)\b'
    ]

    GENERIC_GREETINGS = [
        r'\bdear customer\b',
        r'\bdear user\b',
        r'\bvalued client\b',
        r'\bdear account holder\b',
        r'\bdear member\b',
        r'\battention: user\b'
    ]

    SUSPICIOUS_CTA_PATTERNS = [
        r'\b(?:click here to verify|click here to login|verify identity now)\b',
        r'\b(?:restore access now|confirm your email|update billing information)\b',
        r'\b(?:download the attachment|open attached pdf|enable macros)\b'
    ]

    def __init__(self):
        self.url_detector = URLPhishingDetector()

    def analyze(self, sender, subject, body):
        sender = sender.strip() if sender else ''
        subject = subject.strip() if subject else ''
        body = body.strip() if body else ''

        indicators = []
        risk_score = 10
        total_concerns = 0

        # Parse sender format: "Display Name <email@domain.com>" or "email@domain.com"
        sender_email = sender
        sender_name = sender
        match = re.search(r'^(.*?)\s*<([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)>', sender)
        if match:
            sender_name = match.group(1).strip().strip('"').strip("'")
            sender_email = match.group(2).strip()
        else:
            email_only_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', sender)
            if email_only_match:
                sender_email = email_only_match.group(1)

        sender_domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ''

        # 1. Sender Impersonation / Free Mail Check
        sender_spoof_flag = False
        lower_sender_name = sender_name.lower()
        for org, legitimate_domains in self.TRUSTED_ORGANIZATIONS.items():
            if org in lower_sender_name:
                if sender_domain in self.FREE_EMAIL_PROVIDERS or sender_domain not in legitimate_domains:
                    risk_score += 40
                    total_concerns += 1
                    sender_spoof_flag = True
                    indicators.append({
                        'id': 'sender_spoofing',
                        'name': 'Executive / Brand Impersonation',
                        'severity': 'critical',
                        'status': 'danger',
                        'icon': 'user-x',
                        'value': f'{sender_name} via {sender_domain}',
                        'description': f'Display name mimics official entity "{sender_name}", but the sending domain ({sender_domain}) is unofficial.',
                        'rationale': 'Attackers routinely configure display names to resemble legitimate brands while dispatching from unauthorized mail servers.'
                    })
                    break

        if not sender_spoof_flag and sender_domain in self.FREE_EMAIL_PROVIDERS:
            # If subject mentions banking/account but sent from gmail
            if any(term in (subject + body).lower() for term in ['invoice', 'bank', 'payroll', 'account suspension', 'wire']):
                risk_score += 25
                total_concerns += 1
                indicators.append({
                    'id': 'free_mail_business_lure',
                    'name': 'Corporate Subject from Free Email Provider',
                    'severity': 'high',
                    'status': 'warning',
                    'icon': 'mail',
                    'value': sender_domain,
                    'description': f'Official-sounding communication dispatched from a consumer email provider ({sender_domain}).',
                    'rationale': 'Legitimate organizations communicate strictly through corporate registered domain servers.'
                })

        # 2. Urgency and Coercion Analysis
        combined_text = f"{subject} {body}".lower()
        matched_urgency = []
        for pat in self.URGENCY_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            if found:
                matched_urgency.extend(found)

        if matched_urgency:
            score_add = min(30, len(matched_urgency) * 15)
            risk_score += score_add
            total_concerns += 1
            indicators.append({
                'id': 'urgency_coercion',
                'name': 'Artificial Urgency & Fear Tactics',
                'severity': 'high',
                'status': 'danger',
                'icon': 'clock',
                'value': ', '.join(list(set(matched_urgency))[:3]),
                'description': f'Detected manipulative urgency phrasing: "{", ".join(list(set(matched_urgency))[:3])}".',
                'rationale': 'Phishing lures exploit the emotional response to time pressure (FOMO/fear of loss) to bypass cautious deliberation.'
            })

        # 3. Credential Harvesting Lure
        matched_cred = []
        for pat in self.CREDENTIAL_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            if found:
                matched_cred.extend(found)

        if matched_cred:
            risk_score += 35
            total_concerns += 1
            indicators.append({
                'id': 'credential_harvesting',
                'name': 'Sensitive Credential Solicitation',
                'severity': 'critical',
                'status': 'danger',
                'icon': 'shield-alert',
                'value': ', '.join(list(set(matched_cred))[:3]),
                'description': f'Direct or indirect solicitation of confidential credentials or identity tokens.',
                'rationale': 'Legitimate service providers will never request passwords, recovery keys, or PINs via email messages.'
            })

        # 4. Financial & Extortion Scams
        matched_scam = []
        for pat in self.FINANCIAL_SCAM_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            if found:
                matched_scam.extend(found)

        if matched_scam:
            risk_score += 25
            total_concerns += 1
            indicators.append({
                'id': 'financial_scam',
                'name': 'Irregular Financial Solicitation',
                'severity': 'high',
                'status': 'danger',
                'icon': 'dollar-sign',
                'value': ', '.join(list(set(matched_scam))[:3]),
                'description': 'Mentions unverified invoices, gift cards, or unconventional funds transfers.',
                'rationale': 'Gift cards and non-reversible transfers are irreversible payment vectors heavily exploited by cybercriminals.'
            })

        # 5. Generic Salutation Check
        matched_greeting = []
        for pat in self.GENERIC_GREETINGS:
            found = re.findall(pat, body, re.IGNORECASE)
            if found:
                matched_greeting.extend(found)

        if matched_greeting:
            risk_score += 15
            total_concerns += 1
            indicators.append({
                'id': 'generic_greeting',
                'name': 'Impersonal / Generic Greeting',
                'severity': 'medium',
                'status': 'warning',
                'icon': 'help-circle',
                'value': matched_greeting[0].title(),
                'description': f'Uses non-personalized salutation ("{matched_greeting[0].title()}").',
                'rationale': 'Mass phishing campaigns use generic salutations because attackers blast millions of recipients without full subscriber names.'
            })

        # 6. Aggressive Call-to-Action (CTA)
        matched_cta = []
        for pat in self.SUSPICIOUS_CTA_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            if found:
                matched_cta.extend(found)

        if matched_cta:
            risk_score += 20
            total_concerns += 1
            indicators.append({
                'id': 'aggressive_cta',
                'name': 'High-Pressure Call To Action',
                'severity': 'medium',
                'status': 'warning',
                'icon': 'mouse-pointer',
                'value': ', '.join(list(set(matched_cta))[:2]),
                'description': 'Directs recipient toward immediate off-platform links or attachment downloads.',
                'rationale': 'Fraudulent campaigns channel traffic toward controlled landing pages to extract credentials.'
            })

        # 7. Embedded URL Extraction and Correlated Inspection
        extracted_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        scanned_urls_summary = []
        if extracted_urls:
            has_dangerous_url = False
            for u in extracted_urls[:4]:
                url_eval = self.url_detector.analyze(u)
                scanned_urls_summary.append({
                    'url': u,
                    'score': url_eval['risk_score'],
                    'level': url_eval['risk_level'],
                    'badge': url_eval['risk_badge']
                })
                if url_eval['risk_score'] >= 65:
                    has_dangerous_url = True

            if has_dangerous_url:
                risk_score += 35
                total_concerns += 1
                indicators.append({
                    'id': 'malicious_link_embedded',
                    'name': 'High-Risk URL Embedded in Body',
                    'severity': 'critical',
                    'status': 'danger',
                    'icon': 'link-2',
                    'value': f'{len(extracted_urls)} link(s) found',
                    'description': 'One or more links within the email body trigger critical phishing flags.',
                    'rationale': 'Embedded phishing landing pages are the primary delivery payload for credential theft.'
                })
            else:
                indicators.append({
                    'id': 'links_present',
                    'name': 'Web Hyperlinks Detected',
                    'severity': 'low',
                    'status': 'info',
                    'icon': 'link',
                    'value': f'{len(extracted_urls)} links detected',
                    'description': 'The email contains clickable hyperlinks. Always inspect targets before clicking.',
                    'rationale': 'Verify that the destination URL matches the official brand website.'
                })
        else:
            indicators.append({
                'id': 'no_links',
                'name': 'No Embedded Hyperlinks Found',
                'severity': 'none',
                'status': 'pass',
                'icon': 'check-circle-2',
                'description': 'No external URLs detected in email body content.',
                'rationale': 'Reduces the direct vector for immediate click-redirect credential harvesting.'
            })

        # Cap score between 5 and 99
        risk_score = max(8, min(99, risk_score))

        # Risk Classification
        if risk_score >= 70:
            risk_level = 'PHISHING LIKELY'
            risk_badge = 'danger'
            recommendation = (
                "THREAT DETECTED: This message displays multiple acute characteristics of a social engineering "
                "or phishing attack. Do NOT click any links, open attachments, or reply. "
                "Mark as Phishing/Spam immediately and alert your organization's IT security team."
            )
        elif risk_score >= 45:
            risk_level = 'POSSIBLE PHISHING'
            risk_badge = 'danger'
            recommendation = (
                "HIGH SUSPICION: Significant social engineering triggers or sender inconsistencies detected. "
                "Contact the purported sender using a previously known, verified phone number or portal, "
                "and do not use any contact info provided in this email."
            )
        elif risk_score >= 25:
            risk_level = 'SUSPICIOUS'
            risk_badge = 'warning'
            recommendation = (
                "MODERATE CAUTION: Some unusual patterns identified (e.g. urgency or generic greeting). "
                "Verify the sender address carefully and inspect destination links before interacting."
            )
        else:
            risk_level = 'LOW RISK'
            risk_badge = 'success'
            recommendation = (
                "LEGITIMATE INDICATORS: This communication does not exhibit obvious deception triggers or "
                "phishing hallmarks. Follow standard organizational security guidelines."
            )

        return {
            'sender': sender,
            'sender_name': sender_name,
            'sender_email': sender_email,
            'sender_domain': sender_domain,
            'subject': subject,
            'body_snippet': body[:200] + ('...' if len(body) > 200 else ''),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_badge': risk_badge,
            'indicators': indicators,
            'concern_count': total_concerns,
            'extracted_urls': scanned_urls_summary,
            'recommendation': recommendation
        }
