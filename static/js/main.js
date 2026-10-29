/* ==========================================================================
   PHISHGUARD - Core Interactive JavaScript
   Navigation, Accordions, Alerts, Micro-interactions
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Mobile Menu Drawer Toggle
  const hamburgerBtn = document.getElementById('hamburgerBtn');
  const mobileDrawer = document.getElementById('mobileDrawer');
  const closeDrawerBtn = document.getElementById('closeDrawerBtn');

  if (hamburgerBtn && mobileDrawer) {
    hamburgerBtn.addEventListener('click', () => {
      mobileDrawer.classList.add('open');
      document.body.style.overflow = 'hidden';
    });

    const closeHandler = () => {
      mobileDrawer.classList.remove('open');
      document.body.style.overflow = '';
    };

    if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', closeHandler);
    mobileDrawer.addEventListener('click', (e) => {
      if (e.target === mobileDrawer) closeHandler();
    });
  }

  // 2. Dashboard Sidebar Toggle (on mobile screens)
  const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
  const dashboardSidebar = document.getElementById('dashboardSidebar');
  const sidebarCloseBtn = document.getElementById('sidebarCloseBtn');
  const sidebarBackdrop = document.getElementById('sidebarBackdrop');

  const closeSidebar = () => {
    if (dashboardSidebar) dashboardSidebar.classList.remove('open');
    if (sidebarBackdrop) sidebarBackdrop.classList.remove('active');
  };

  if (sidebarToggleBtn && dashboardSidebar) {
    sidebarToggleBtn.addEventListener('click', () => {
      const isOpen = dashboardSidebar.classList.toggle('open');
      if (sidebarBackdrop) {
        sidebarBackdrop.classList.toggle('active', isOpen);
      }
    });
  }

  if (sidebarCloseBtn) sidebarCloseBtn.addEventListener('click', closeSidebar);
  if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', closeSidebar);

  // 3. Navbar scroll effect
  const navbar = document.querySelector('.navbar');
  if (navbar) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 20) {
        navbar.classList.add('navbar-scrolled');
      } else {
        navbar.classList.remove('navbar-scrolled');
      }
    });
  }

  // 4. Accordion Toggle
  const accordionItems = document.querySelectorAll('.accordion-item');
  accordionItems.forEach(item => {
    const header = item.querySelector('.accordion-header');
    if (header) {
      header.addEventListener('click', () => {
        const isActive = item.classList.contains('active');
        // Close others in same accordion group if needed or toggle
        item.classList.toggle('active', !isActive);
      });
    }
  });

  // 5. Flash Alerts Auto-dismiss
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach(alert => {
    setTimeout(() => {
      alert.style.opacity = '0';
      alert.style.transform = 'translateY(-10px)';
      alert.style.transition = 'all 0.3s ease';
      setTimeout(() => alert.remove(), 300);
    }, 4500);
  });

  // 6. Awareness Modal Close Button & Backdrop Handler
  const modalOverlay = document.getElementById('awarenessModalOverlay');
  const modalCloseBtn = document.getElementById('modalCloseBtn');

  if (modalOverlay) {
    if (modalCloseBtn) {
      modalCloseBtn.addEventListener('click', closeAwarenessModal);
    }
    modalOverlay.addEventListener('click', (e) => {
      if (e.target === modalOverlay) {
        closeAwarenessModal();
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modalOverlay.classList.contains('open')) {
        closeAwarenessModal();
      }
    });
  }
});

/* ==========================================================================
   AWARENESS TRAINING DATA DICTIONARY & MODAL CONTROLLER
   ========================================================================== */
const AWARENESS_TOPICS = {
  what_is_phishing: {
    title: "What is Phishing?",
    tag: "Module 01 • Fundamentals",
    overview: "Phishing is a deceptive social engineering attack where malicious actors impersonate trusted organizations (banks, cloud providers, employers) to manipulate individuals into disclosing sensitive credentials, financial data, or launching malware payloads.",
    scenarioTitle: "Simulated Attack: The Bogus IT Security Reset",
    scenarioText: "You receive an email appearing to come from your company IT team warning that 'Your corporate portal password expires in 2 hours'. A link directs you to an identical-looking login page where your credentials are saved by attackers.",
    redFlags: [
      "Artificial, urgent deadlines threatening loss of access if not resolved immediately",
      "Generic greetings like 'Dear Employee' instead of your verified legal name",
      "Discrepancies between the display sender name and the actual domain (@company-sec-reset.xyz)",
      "Unsolicited credential prompts originating from external hyperlink redirects"
    ],
    defenseSteps: [
      "Always navigate independently to your corporate portal instead of following email links",
      "Verify unexpected IT notices via your internal messaging directory or helpdesk extension",
      "Inspect the browser address bar for correct domain spelling and valid HTTPS TLS encryption",
      "Enable hardware security keys (FIDO2) or authenticator apps to protect credentials"
    ]
  },
  email_phishing: {
    title: "Email Phishing & BEC (Spear Phishing)",
    tag: "Module 02 • Email Vectors",
    overview: "Business Email Compromise (BEC) and targeted spear phishing manipulate organizational hierarchy and vendor relationships. Attackers impersonate executives, suppliers, or legal counsel to execute fraudulent fund transfers or exfiltrate trade secrets.",
    scenarioTitle: "Simulated Attack: The CEO Urgent Wire Transfer",
    scenarioText: "An email arrives from the CEO's name requesting an immediate wire transfer of $18,500 for a confidential vendor acquisition, insisting they are in an executive board meeting and cannot take phone calls.",
    redFlags: [
      "Executive requesting urgent financial transactions bypassing standard authorization workflows",
      "Sender email domain is slightly misspelled or sent from an external consumer account (e.g. ceo@gmail.com)",
      "Strict instructions to maintain secrecy and avoid standard verification protocols",
      "Uncharacteristic tone, grammar anomalies, or coercive pressure tactics"
    ],
    defenseSteps: [
      "Establish strict out-of-band phone verification for all financial disbursements",
      "Require multi-person sign-off for invoice changes or banking detail updates",
      "Inspect email headers for spoofed 'Reply-To' addresses differing from the sender",
      "Never alter wire payment instructions based solely on an electronic message"
    ]
  },
  smishing_vishing: {
    title: "Smishing & Vishing (SMS & Voice Phishing)",
    tag: "Module 03 • Mobile Threats",
    overview: "Smishing (SMS phishing) and Vishing (voice call phishing) exploit mobile devices. Attackers capitalize on shorter attention spans on mobile screens to harvest banking logins and multi-factor authentication codes.",
    scenarioTitle: "Simulated Attack: The Postal Redelivery Scam",
    scenarioText: "A text message arrives: 'USPS Notice: Package #US92817 cannot be delivered due to invalid street address. Update within 12 hours at https://usps-parcel-redeliver.top or parcel is returned to sender'.",
    redFlags: [
      "Unsolicited SMS from full 10-digit consumer phone numbers rather than verified 5-digit shortcodes",
      "Suspicious top-level domains such as .top, .xyz, or .club embedded in SMS links",
      "Requests to pay nominal fees ($1.50) using credit card details to harvest payment cards",
      "Callers demanding immediate OTP or 2FA codes claiming to be your bank's fraud team"
    ],
    defenseSteps: [
      "Never click tracking links inside unexpected SMS text messages",
      "Track parcels exclusively on the official carrier app or bookmarked website",
      "Never recite or send 2FA SMS verification codes over phone calls to anyone",
      "Block and report scam SMS numbers directly to your mobile carrier (forward to 7726)"
    ]
  },
  social_engineering: {
    title: "Social Engineering Psychology",
    tag: "Module 04 • Human Factor",
    overview: "Social engineering targets human vulnerabilities rather than software weaknesses. Attackers leverage authority, fear of negative consequences, helpfulness, curiosity, and reciprocity to manipulate targets into violating security protocols.",
    scenarioTitle: "Simulated Attack: The Helpful Vendor Pretext",
    scenarioText: "A caller claims to be a contracted photocopier technician needing network credentials to test printer firmware before the office closes for the weekend, offering to fix pending errors.",
    redFlags: [
      "High urgency mixed with an appeal to avoid getting a colleague in trouble",
      "Requests for access credentials or physical entry into restricted server rooms",
      "Unsolicited offers of technical assistance for problems you did not report",
      "Attempts to elicit corporate structural information or employee names"
    ],
    defenseSteps: [
      "Always enforce identity verification and physical visitor badge sign-in protocols",
      "Adhere strictly to corporate security procedures regardless of caller rank or urgency",
      "Escalate suspicious inquiries immediately to your security officer",
      "Practice healthy skepticism when asked to bypass established procedures"
    ]
  },
  fake_websites: {
    title: "Fake Websites & Typosquatting",
    tag: "Module 05 • Domain Spoofing",
    overview: "Attackers register deceptive domain names that closely mirror legitimate brands. Techniques include typosquatting (swapping letters for numbers like 'paypa1.com') and combobulating words ('chase-bank-verify.com').",
    scenarioTitle: "Simulated Attack: The Cloned Banking Portal",
    scenarioText: "You type a search query for your bank and accidentally click an ad directing to `wellsfarg0-online.com`. The portal is an exact visual replica designed to capture account numbers and passwords.",
    redFlags: [
      "Subtle letter substitutions (e.g. 'rn' resembling 'm', digit '1' for lowercase 'l')",
      "Domain contains legitimate brand name but followed by hyphens and security words",
      "Absence of expected organization name in browser security certificate details",
      "Website layout appears broken, links outside the login box are dead, or copyright is outdated"
    ],
    defenseSteps: [
      "Bookmark critical financial and authentication websites rather than searching for them",
      "Inspect the primary domain name in your address bar before typing passwords",
      "Use password managers with auto-fill; they will never autofill on spoofed domains",
      "Run suspicious links through the PhishGuard URL Scanner before navigating"
    ]
  },
  password_safety: {
    title: "Password Safety & Credential Defense",
    tag: "Module 06 • Credential Security",
    overview: "Weak, predictable, or recycled passwords provide cybercriminals with instant access to your digital footprint through credential stuffing attacks and automated dictionary tools.",
    scenarioTitle: "Simulated Attack: The Credential Stuffing Breach",
    scenarioText: "An old entertainment forum suffers a database breach. Attackers test the leaked email and password across email providers, banks, and corporate VPNs, instantly penetrating accounts that reused credentials.",
    redFlags: [
      "Receiving 'New login from unrecognized device' notifications unexpectedly",
      "Using the same password or simple variations (e.g. Spring2026!) across multiple services",
      "Using easily guessable personal info (pet names, birth years, children's names)",
      "Storing passwords in unencrypted plain text notes or spreadsheet documents"
    ],
    defenseSteps: [
      "Construct 16+ character passphrases composed of random words (e.g., 'Solar#Bicycle#Crimson#94')",
      "Deploy an encrypted password manager (Bitwarden, 1Password) to generate unique credentials",
      "Never recycle passwords between corporate and personal environments",
      "Check breach notification services like haveibeenpwned.com routinely"
    ]
  },
  mfa_security: {
    title: "Multi-Factor Authentication (MFA)",
    tag: "Module 07 • Access Control",
    overview: "Multi-Factor Authentication requires two or more verification factors before granting access. While highly effective, cybercriminals use tactics like MFA fatigue and SIM swapping to bypass standard defenses.",
    scenarioTitle: "Simulated Attack: The 3:00 AM Prompt Bombing",
    scenarioText: "Your phone is bombarded with dozens of push notifications asking you to approve a login attempt in the middle of the night, followed by a text claiming to be IT asking you to accept to clear an alert.",
    redFlags: [
      "Receiving authentication push prompts or SMS codes when you are not actively logging in",
      "Rapid succession of repeated MFA requests intended to induce fatigue or frustration",
      "Anyone asking you to read back a multi-digit one-time passcode over the phone",
      "Sudden loss of cellular reception (possible indicator of a SIM swap attempt)"
    ],
    defenseSteps: [
      "Always click 'Deny' or 'Report Suspicious Activity' on unexpected MFA prompts",
      "Immediately change your account password if unsolicited MFA prompts begin appearing",
      "Prefer FIDO2 hardware security keys (YubiKey) or time-based OTP apps over SMS",
      "Enable number matching on authentication push prompts to prevent accidental approval"
    ]
  },
  safe_browsing: {
    title: "Safe Browsing & File Downloads",
    tag: "Module 08 • Web Hygiene",
    overview: "Web browsers are the primary window to digital resources. Attackers deploy malicious drive-by downloads, compromised browser extensions, and deceptive double file extensions to deploy spyware and ransomware.",
    scenarioTitle: "Simulated Attack: The Masked Executable (.pdf.exe)",
    scenarioText: "You download what appears to be an invoice named `Quarterly_Receipt.pdf`. Because Windows hides file extensions by default, the full file name is `Quarterly_Receipt.pdf.exe` and launches malware when opened.",
    redFlags: [
      "Files with double extensions (e.g. .pdf.exe, .docx.scr, .jpg.vbs)",
      "Downloads that automatically trigger without your explicit user click",
      "Browser warning that 'This file is not commonly downloaded and may be dangerous'",
      "Prompts to install a browser extension to view content or solve a CAPTCHA"
    ],
    defenseSteps: [
      "Enable 'File name extensions' visibility in Windows Explorer settings",
      "Scan downloaded files with antivirus software or VirusTotal before executing",
      "Never enable macros or click 'Enable Content' in office documents from external sources",
      "Keep your web browser and operating system updated with the latest security patches"
    ]
  }
};

function openAwarenessModal(topicKey) {
  const modal = document.getElementById('awarenessModalOverlay');
  const data = AWARENESS_TOPICS[topicKey];

  if (!modal || !data) return;

  document.getElementById('modalTag').textContent = data.tag;
  document.getElementById('modalTitle').textContent = data.title;
  document.getElementById('modalOverview').textContent = data.overview;
  document.getElementById('modalScenarioTitle').textContent = data.scenarioTitle;
  document.getElementById('modalScenarioText').textContent = data.scenarioText;

  const redFlagsList = document.getElementById('modalRedFlagsList');
  redFlagsList.innerHTML = data.redFlags.map(rf => `
    <li><span>⚠</span> <div>${rf}</div></li>
  `).join('');

  const defenseList = document.getElementById('modalDefenseList');
  defenseList.innerHTML = data.defenseSteps.map(ds => `
    <li><span>✓</span> <div>${ds}</div></li>
  `).join('');

  modal.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeAwarenessModal() {
  const modal = document.getElementById('awarenessModalOverlay');
  if (modal) {
    modal.classList.remove('open');
    document.body.style.overflow = '';
  }
}
