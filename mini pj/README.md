# PHISHGUARD 🛡️
### Phishing Attack Detection & Awareness System
**College Mini Project**

---

### Project Attribution
* **Student Developer:** Chauhan Brijesh Ramayan
* **Project Mentor:** Jagruti Raut
* **Academic Classification:** College Mini Project

---

## 🌐 Overview & UI/UX Inspiration
**PHISHGUARD** is a commercial-grade, explainable cybersecurity intelligence and awareness platform designed to protect users against phishing attacks and social engineering deception.

Inspired by modern cybersecurity platforms (such as the Dribbble reference: *Cybersecurity Awareness Training Platform Website*), PhishGuard rejects the appearance of a basic CRUD college project, delivering a cohesive cybersecurity design language featuring:
* Deep navy and cyber blue/cyan palette (`#0B132B`, `#0284C7`, `#06B6D4`)
* Crisp, rounded glassmorphic cards and badges
* Dynamic radial risk score gauge (0-100)
* High-speed heuristic threat analysis without black-box opacity
* Continuous interactive user training through a 4-stage awareness pipeline and a 10-scenario certification quiz

---

## 🚀 Key Platform Features

### 1. Polished 11-Section Landing Page
1. **Modern Minimalist Navbar:** Brand shield emblem, responsive navigation links, and mobile slide-out drawer.
2. **Hero Section:** Large typography, "Detect Phishing. Build Cyber Awareness.", dual CTAs, and a live cybersecurity telemetry card with active pulse status.
3. **Trust & Value Statement:** High-impact cards highlighting why human awareness is the primary line of cyber defense (91% of intrusions begin with phishing).
4. **How It Works (3-Step Visual Flow):** 01 Enter &rarr; 02 Analyze &rarr; 03 Understand.
5. **Core Feature Suite:** 6 interactive cards detailing the URL Scanner, Email Analyzer, Risk Scoring, Audit Reports, Awareness Hub, and Cyber Quiz.
6. **URL Scanner Live Preview:** Interactive input with preset sample chips ("Google Auth", "PayPal Typosquat", "URL Shortener", "Raw IP") and live risk assessment preview.
7. **Email Analyzer Preview:** Realistic suspicious email mock card with flagged indicators and analysis summary.
8. **Awareness Center Preview:** 8 core cybersecurity topics (Phishing, BEC, Smishing, Social Engineering, Typosquatting, Passwords, MFA, Safe Browsing).
9. **Interactive Quiz Promo:** Direct invitation to test phishing instincts across 10 realistic scenarios.
10. **System Statistics:** 5 detection modules, 10+ awareness topics, 10 quiz questions, and 100% explainable results.
11. **Final Call-to-Action:** High-contrast CTA section with quick links and project attribution footer.

---

### 2. URL Phishing Detection Engine (`detectors/url_detector.py`)
Analyzes web addresses against 14 lexical and structural heuristics:
* **Protocol & TLS Encryption:** Detects plain unencrypted HTTP vs verified HTTPS.
* **IP Address as Hostname:** Identifies raw IPv4/IPv6 addresses used to bypass DNS registries.
* **Brand Impersonation & Typosquatting:** Monitors trademarks (PayPal, Google, Apple, Microsoft, Netflix, Amazon, Facebook, Chase, Wells Fargo, etc.) and flags unauthorized permutations.
* **Excessive Subdomain Tunneling:** Uncovers multi-level nested subdomains designed to conceal true destinations on mobile browsers.
* **Embedded Credential Routing (`@`):** Flags browser credential redirection syntax.
* **Double Slash (`//`) in Path:** Identifies open-redirect bypass tricks.
* **URL Shortener Services:** Detects masked destinations (Bit.ly, TinyURL, t.co, etc.).
* **High-Risk Disposable TLDs:** Flags extensions frequently exploited in mass phishing kits (`.xyz`, `.top`, `.work`, `.club`, `.tk`, etc.).
* **Punycode / Homograph (IDN) Attacks:** Identifies Cyrillic/Greek lookalike characters (`xn--`).
* **Non-Standard Ports & Hex Obfuscation:** Flags anomalous ports (`:8080`, `:8888`) and percent-encoded evasion scripts.

---

### 3. Email Threat Analyzer (`detectors/email_detector.py`)
Inspects incoming messages for social engineering hallmarks:
* **Display Name vs Sender Domain Spoofing:** Flags corporate display names dispatched from free consumer mailboxes (e.g. Gmail) or untrusted domains.
* **Psychological Urgency & Fear Tactics:** Detects artificial deadlines ("within 24 hours", "account will be terminated immediately", "unauthorized login").
* **Sensitive Credential Harvesting:** Identifies solicitations for passwords, PINs, OTP codes, social security numbers, or wire transfers.
* **Financial & Gift Card Scams:** Recognizes CEO fraud (BEC) requesting gift cards or urgent invoices.
* **Generic Greetings:** Flags mass-phishing indicators ("Dear Customer", "Valued User").
* **Correlated Embedded Link Telemetry:** Extracts all body hyperlinks and passes them through the URL heuristic engine for correlated threat scoring.

---

### 4. Interactive Awareness Hub & Certification Quiz
* **4-Stage Learning Pipeline:**
  * **01 Learn Foundations:** In-depth coverage of 8 distinct cyber threat vectors.
  * **02 Recognize Red Flags:** Interactive dissection of deceptive email anatomy.
  * **03 Practice Defensive Rules:** Side-by-side Do's and Don'ts rulecards.
  * **04 Test Yourself:** Direct launchpad to the 10-scenario knowledge quiz.
* **10-Question Cyber Challenge:** Realistic workplace and consumer scenarios with instant explanations for every choice.
* **Printable Accreditation Certificate:** Generates a personalized *Certificate of Phishing Awareness* with student name, date, score percentage, and credential ID.

---

### 5. Application Dashboard & Telemetry Reports
* **Personalized Operator Dashboard:** Time-of-day greeting ("Good morning, Brijesh"), active status indicators, and 4 metric cards (Total Scans, Safe Links, Suspicious, High Risk).
* **Quick Scanner Widget:** Instant URL scanning directly inside the operations portal.
* **Recent Activity Feed:** Chronological table displaying evaluated targets, risk scores, classifications, and inspect links.
* **Security Audit Reports:** Filter by status (All, Safe, Suspicious, High Risk), search by keyword/domain, print reports, or export entire logs to CSV.

---

## 🛠️ Technology Stack
* **Backend Framework:** Python 3.13 / Flask 3.1
* **Database Architecture:** Dual Engine
  * **MySQL / MariaDB:** Full production DDL schema provided (`schema.sql`).
  * **SQLite:** Automatic zero-configuration fallback (`phishguard.db`) so the project runs immediately out-of-the-box without requiring external database server startup.
* **Security & Auth:** Werkzeug password hashing (Scrypt/PBKDF2), HTTP sessions, SQL parameter binding.
* **Frontend:** Vanilla HTML5, CSS3 Custom Properties, Responsive Flexbox/Grid, SVG icon vectors, Vanilla ES6 JavaScript (No bloated external dependencies).
* **Testing:** PyTest automated testing suite (14 test cases covering unit heuristics, threat classification, and route integration).

---

## ⚡ Installation & Quick Start

### 1. Clone or Open Project Directory
```powershell
cd "c:\Users\ramay\OneDrive\Desktop\mini pj"
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Run the Application
```powershell
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🔑 Default Evaluation Credentials
The database is pre-seeded with an administrator profile for evaluation:
* **Email:** `brijesh@phishguard.local`
* **Password:** `password123`
*(A quick auto-fill button is also provided on the login page for convenience!)*

---

## 🗄️ Database Setup (MySQL vs SQLite)

### Automatic SQLite Mode (Default)
When you run `python app.py`, the system tests if a local MySQL instance is reachable. If not running, it **automatically initializes `phishguard.db`** with all tables and seed data. No manual database configuration is required!

### MySQL Mode (Optional)
To use MySQL/XAMPP:
1. Start your MySQL service on port `3306`.
2. Configure credentials in `config.py` (or set environment variables `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DB`).
3. Import `schema.sql` into MySQL:
   ```bash
   mysql -u root -p < schema.sql
   ```
4. Restart `python app.py`. PhishGuard will detect MySQL and connect automatically.

---

## 🧪 Automated Testing
Run the comprehensive PyTest suite:
```powershell
python -m pytest tests/ -v
```
All 14 test cases validate:
* Safe URL evaluation and verified checkmarks
* Brand spoofing and typosquatting detection
* Raw IP address and shortened URL detection
* Punycode homograph attack identification
* Email urgency, gift card lure, and sender mismatch detection
* Flask route responses, quiz API submission, and CSV export functionality

---

## ☁️ Deployment Guide

### Option 1: Deploy on Netlify (Serverless Python Functions)
PhishGuard includes pre-configured **`netlify.toml`** and serverless entrypoint **`netlify/functions/app.py`** powered by `serverless-wsgi`:
1. **Push your code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Deploy PHISHGUARD to Netlify"
   git branch -M main
   git remote add origin https://github.com/<your-username>/phishguard.git
   git push -u origin main
   ```
2. **Connect to Netlify:**
   * Go to [Netlify Dashboard](https://app.netlify.com) &rarr; Click **"Add new site"** &rarr; **"Import an existing project"**.
   * Select **GitHub** and pick your `phishguard` repository.
3. **Build Settings:**
   * Netlify automatically reads `netlify.toml`!
   * **Publish directory:** `static`
   * **Functions directory:** `netlify/functions`
   * **Environment variables:** You may add `SECRET_KEY` (e.g. `phishguard-production-key-2026`).
4. Click **Deploy Site**. Netlify compiles the serverless lambda functions and serves your website worldwide!

---

### Option 2: Deploy on Render.com (Recommended for Persistent Storage)
Render runs the application as a full persistent WSGI container via Gunicorn:
1. Push repository to GitHub.
2. Sign up on [Render.com](https://render.com) (Free Tier available).
3. Click **"New +"** &rarr; **"Web Service"** &rarr; Connect your GitHub repository.
4. Settings:
   * **Runtime:** `Python 3`
   * **Build Command:** `pip install -r requirements.txt`
   * **Start Command:** `gunicorn app:app` (Render automatically detects `Procfile`)
5. Click **Deploy Web Service** &mdash; your live HTTPS URL is ready in 2 minutes!

---

## 📱 Mobile & Cross-Device Optimization
PHISHGUARD is engineered with responsive, touch-friendly UI for:
* **Android Smartphones & Tablets:** Seamless touch menus, 44px minimum tap targets, full-width inputs, and auto-zoom prevention (`font-size: 16px` on focus).
* **iPhones & iPads:** Backdrop-filtered drawer menus, `-webkit-overflow-scrolling: touch`, and flexible SVG gauges.
* **Laptops & Large Desktops:** Clean multi-column grids, hovering cards, sticky topbars, and typography scaling via CSS `clamp()`.

---

## 🎓 Academic Submission Information
* **Project Name:** PHISHGUARD
* **Subtitle:** Phishing Attack Detection & Awareness System
* **Author:** Chauhan Brijesh Ramayan
* **Project Guide / Mentor:** Jagruti Raut
* **College Mini Project:** Academic Year 2025–2026
