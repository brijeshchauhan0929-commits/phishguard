/* ==========================================================================
   PHISHGUARD - Interactive Cybersecurity Quiz Engine
   10 Realistic Scenarios, Instant Feedback, Explanations, & Certificate
   ========================================================================== */

const QUIZ_QUESTIONS = [
  {
    category: "Smishing & SMS Phishing",
    scenario: "You receive an SMS message: 'USPS Notice: Your package could not be delivered due to an incomplete address. Update your shipping details within 12 hours at https://usps-tracking-parcel.top/update or package will be returned to sender.'",
    question: "What is the safest and most appropriate course of action?",
    options: [
      "Click the link quickly to make sure your package isn't returned.",
      "Reply with 'STOP' to unsubscribe from future messages.",
      "Do not click the link; inspect the domain (.top extension) and verify directly on the official USPS.com website if you are expecting a package.",
      "Call the phone number that texted you to confirm their identity."
    ],
    correctIndex: 2,
    explanation: "This is a classic 'Smishing' lure. Legitimate postal carriers do not use disposable .top domains. Attackers create false urgency ('within 12 hours') to induce panic. Replying or calling confirms your number is active."
  },
  {
    category: "Domain Typosquatting",
    scenario: "You receive an email asking you to verify your PayPal transaction. When you hover over the verification button, the URL preview shows: 'http://paypa1-security-verification.com/login?token=92847'.",
    question: "Which critical red flag is present in this URL?",
    options: [
      "The token number at the end is too short.",
      "The domain uses typosquatting (substituting the letter 'l' with the digit '1') and plain HTTP protocol.",
      "The URL contains a question mark, which is strictly prohibited on the web.",
      "There are no red flags; this is the standard backup domain for PayPal."
    ],
    correctIndex: 1,
    explanation: "Notice 'paypa1' contains the number '1' instead of lowercase 'l' (Typosquatting/Homoglyph attack). Furthermore, legitimate financial portals exclusively mandate HTTPS encryption."
  },
  {
    category: "Business Email Compromise (BEC)",
    scenario: "An email arrives from your CEO's address: 'I am currently in an urgent meeting with investors. Please wire $18,500 to this vendor account by 2:00 PM for project clearance. Treat this urgently.'",
    question: "How should you respond to this urgent financial request?",
    options: [
      "Wire the funds immediately since the CEO specifically marked it urgent.",
      "Reply directly to the email asking for confirmation of the bank details.",
      "Follow established financial verification procedures by contacting the CEO via a known phone number or in-person before transferring any funds.",
      "Forward the email to your personal account so you have a copy."
    ],
    correctIndex: 2,
    explanation: "This is an executive impersonation attack (CEO Fraud). Attackers rely on authority pressure and artificial deadlines. Never confirm financial requests by replying to the same email; always use an independent out-of-band communication channel."
  },
  {
    category: "Hyperlink Deception",
    scenario: "An email notification displays the text 'https://www.chase.com/secure-login'. However, when you hover your mouse cursor over it, your browser displays the actual destination: 'http://chase-portal.account-security.net/auth'.",
    question: "What does this discrepancy indicate?",
    options: [
      "This is standard practice for modern web routing.",
      "The email is a phishing attempt where the visible text is disguising a malicious destination.",
      "The email client is experiencing an encoding glitch.",
      "Chase Bank has migrated to a new domain name."
    ],
    correctIndex: 1,
    explanation: "HTML allows anchor text to display one URL while the underlying 'href' attribute navigates to a completely different server. Always rely on the actual status bar URL preview, not the visible display text."
  },
  {
    category: "MFA Fatigue Attacks",
    scenario: "At 2:30 AM, you suddenly receive dozens of consecutive push notifications on your phone asking you to 'Approve Sign-in' to your work account.",
    question: "What kind of cyberattack are you currently experiencing?",
    options: [
      "A routine system maintenance test by your IT department.",
      "An MFA Fatigue (Prompt Bombing) attack, where an attacker has your password and is trying to overwhelm you into clicking 'Approve'.",
      "A glitch in your cell phone carrier's network.",
      "Your password has expired and you must approve the notification to reset it."
    ],
    correctIndex: 1,
    explanation: "In MFA Fatigue attacks, cybercriminals repeatedly spam authentication requests hoping the exhausted victim will tap 'Approve' to stop the ringing. Never approve unexpected prompts; immediately change your password and notify IT."
  },
  {
    category: "Dangerous File Attachments",
    scenario: "You receive an unexpected email from an unknown sender claiming to be a client: 'Please review the attached overdue invoice: invoice_may2026.pdf.exe'.",
    question: "Why is this attachment dangerous?",
    options: [
      "PDF files cannot be sent via email attachments.",
      "The file uses double extension masking (.pdf.exe) to disguise a malicious executable file as an innocent PDF document.",
      "The word 'invoice' automatically corrupts email files.",
      "The invoice is dated for the current month."
    ],
    correctIndex: 1,
    explanation: "Windows frequently hides known extensions by default. Cybercriminals append '.pdf.exe' so users only see '.pdf', tricking them into launching an executable malware payload."
  },
  {
    category: "Credential Harvesting Lures",
    scenario: "You click a shared link from a colleague and land on a page that looks identical to Microsoft 365, with a message: 'Session Expired. Enter your email password to view this document.' The URL in the address bar is 'https://onedrive-sharepoint-docs.club'.",
    question: "What is happening here?",
    options: [
      "Microsoft has transitioned document hosting to .club domains.",
      "This is a credential harvesting portal mimicking Microsoft to steal your username and password.",
      "Your corporate network requires re-authentication on external web pages.",
      "The shared document is password-protected by the author."
    ],
    correctIndex: 1,
    explanation: "Official Microsoft 365 authentication takes place solely on microsoft.com or microsoftonline.com domains. High-risk TLDs like '.club' hosting login prompts are fake credential harvesters."
  },
  {
    category: "Unrequested Password Resets",
    scenario: "You receive an email stating: 'Your Google password was reset successfully.' You did not request or initiate a password reset.",
    question: "What should be your immediate next step?",
    options: [
      "Click the 'Cancel Reset' link provided inside the email message.",
      "Ignore it; passwords frequently reset themselves automatically.",
      "Navigate independently to google.com, check your recent security activity, review logged-in devices, and change your password.",
      "Forward the email to 5 friends to warn them."
    ],
    correctIndex: 2,
    explanation: "Phishing emails often forge 'Your password was reset' notices containing a fake 'Undo' button that leads directly to a credential-harvesting trap. Always open a fresh browser window and visit the official website directly."
  },
  {
    category: "Public Wi-Fi & Captive Portals",
    scenario: "While sitting in a coffee shop, you connect to 'Free_Public_WiFi'. A pop-up appears asking you to 'Log in with your Google or Facebook password to access the internet'.",
    question: "Why should you never enter your primary account password here?",
    options: [
      "Public Wi-Fi networks can only accept Apple ID credentials.",
      "It may be a rogue Wi-Fi hotspot (Evil Twin) designed to capture credentials entered on fake captive login pages.",
      "Public Wi-Fi speeds decrease if you use Google login.",
      "Free Wi-Fi portals are required by law to know your account password."
    ],
    correctIndex: 1,
    explanation: "Anyone can create a Wi-Fi hotspot named 'Free_Public_WiFi' with a fake landing page (Evil Twin attack). Never enter your actual email or social media passwords into a captive portal."
  },
  {
    category: "Social Media Quid Pro Quo",
    scenario: "A friend's Instagram account suddenly messages you: 'Hey! I'm entering a design competition and need your vote. Can you send me the 6-digit code that Instagram just texted to your phone?'",
    question: "What is actually happening?",
    options: [
      "Your friend genuinely needs votes for a legitimate design competition.",
      "Your friend's account has been compromised, and the hacker is attempting to hijack YOUR account using your SMS Two-Factor Authentication (2FA) recovery code.",
      "Instagram requires two users to share security codes to vote.",
      "This is an automated system verification test."
    ],
    correctIndex: 1,
    explanation: "The attacker triggered an Instagram password reset for your account and is attempting to trick you into surrendering the 2FA one-time verification code. Never share SMS security codes with anyone."
  }
];

let currentQuestionIndex = 0;
let userScore = 0;
let userAnswers = [];

document.addEventListener('DOMContentLoaded', () => {
  const quizApp = document.getElementById('quizApp');
  if (!quizApp) return;

  renderQuestion();
});

function renderQuestion() {
  const container = document.getElementById('quizCardContent');
  const progressFill = document.getElementById('quizProgressFill');
  const counterText = document.getElementById('quizCounter');

  if (!container) return;

  const q = QUIZ_QUESTIONS[currentQuestionIndex];
  const progressPercent = ((currentQuestionIndex) / QUIZ_QUESTIONS.length) * 100;
  if (progressFill) progressFill.style.width = `${progressPercent}%`;
  if (counterText) counterText.textContent = `Question ${currentQuestionIndex + 1} of ${QUIZ_QUESTIONS.length}`;

  const letters = ['A', 'B', 'C', 'D'];

  container.innerHTML = `
    <div class="quiz-scenario-box">
      <span class="quiz-category-tag">${escapeHtml(q.category)}</span>
      <p style="font-size: 1rem; color: #475569; margin-bottom: 12px; line-height: 1.5;">${escapeHtml(q.scenario)}</p>
      <h3 class="quiz-question-text">${escapeHtml(q.question)}</h3>
    </div>

    <div class="quiz-options-list" id="optionsList">
      ${q.options.map((opt, idx) => `
        <button class="quiz-option-btn" data-index="${idx}">
          <span class="option-letter-badge">${letters[idx]}</span>
          <span>${escapeHtml(opt)}</span>
        </button>
      `).join('')}
    </div>

    <div id="feedbackContainer" style="display: none;"></div>

    <div style="display: flex; justify-content: flex-end; margin-top: 24px;">
      <button id="nextBtn" class="btn btn-primary" style="display: none;">
        ${currentQuestionIndex === QUIZ_QUESTIONS.length - 1 ? 'View Final Results & Certificate' : 'Next Scenario →'}
      </button>
    </div>
  `;

  // Attach button click handlers
  const optionButtons = container.querySelectorAll('.quiz-option-btn');
  optionButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const selectedIndex = parseInt(btn.getAttribute('data-index'), 10);
      handleOptionSelected(selectedIndex, optionButtons);
    });
  });
}

function handleOptionSelected(selectedIndex, buttons) {
  const q = QUIZ_QUESTIONS[currentQuestionIndex];
  const isCorrect = selectedIndex === q.correctIndex;

  if (isCorrect) userScore++;
  userAnswers.push({
    questionIndex: currentQuestionIndex,
    selected: selectedIndex,
    correct: q.correctIndex,
    isCorrect: isCorrect
  });

  // Disable all option buttons
  buttons.forEach((btn, idx) => {
    btn.disabled = true;
    if (idx === q.correctIndex) {
      btn.classList.add('correct');
    } else if (idx === selectedIndex && !isCorrect) {
      btn.classList.add('incorrect');
    }
  });

  // Show Feedback Box
  const feedbackContainer = document.getElementById('feedbackContainer');
  const nextBtn = document.getElementById('nextBtn');

  if (feedbackContainer) {
    feedbackContainer.className = `quiz-explanation-box ${isCorrect ? 'correct-feedback' : 'incorrect-feedback'}`;
    feedbackContainer.style.display = 'block';
    feedbackContainer.innerHTML = `
      <div style="font-weight: 800; font-size: 1.05rem; margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">
        ${isCorrect ? '✓ Correct Decision!' : '✗ Critical Security Risk Identified'}
      </div>
      <p style="font-size: 0.92rem; line-height: 1.55;">${escapeHtml(q.explanation)}</p>
    `;
  }

  if (nextBtn) {
    nextBtn.style.display = 'inline-flex';
    nextBtn.addEventListener('click', () => {
      currentQuestionIndex++;
      if (currentQuestionIndex < QUIZ_QUESTIONS.length) {
        renderQuestion();
      } else {
        renderQuizCompletion();
      }
    }, { once: true });
  }
}

function renderQuizCompletion() {
  const container = document.getElementById('quizCardContent');
  const progressFill = document.getElementById('quizProgressFill');
  const counterText = document.getElementById('quizCounter');

  if (progressFill) progressFill.style.width = '100%';
  if (counterText) counterText.textContent = 'Assessment Completed';

  const percentage = Math.round((userScore / QUIZ_QUESTIONS.length) * 100);
  let rating = '';
  let badgeColor = '';

  if (percentage >= 80) {
    rating = 'Cyber Defender (Advanced)';
    badgeColor = 'success';
  } else if (percentage >= 50) {
    rating = 'Security Practitioner (Intermediate)';
    badgeColor = 'warning';
  } else {
    rating = 'Vulnerable to Phishing (Requires Review)';
    badgeColor = 'danger';
  }

  // Attempt to save result to backend API
  fetch('/api/quiz/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      score: userScore,
      total: QUIZ_QUESTIONS.length,
      percentage: percentage,
      rating: rating,
      answers: userAnswers
    })
  }).catch(e => console.log('Quiz saved locally or user is guest.'));

  const studentName = window.PHISHGUARD_USER_NAME || "Chauhan Brijesh Ramayan";
  const today = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  container.innerHTML = `
    <div class="text-center" style="padding: 20px 0;">
      <div style="font-size: 3.5rem; font-weight: 800; color: var(--primary); margin-bottom: 8px;">
        ${userScore} / ${QUIZ_QUESTIONS.length}
      </div>
      <div style="margin-bottom: 16px;">
        <span class="badge badge-${badgeColor}" style="font-size: 0.95rem; padding: 6px 18px;">
          ${rating}
        </span>
      </div>
      <p style="color: var(--text-muted); max-width: 580px; margin: 0 auto 36px auto;">
        You achieved an overall score of <strong>${percentage}%</strong>. Continue maintaining rigorous digital hygiene, inspecting suspicious URLs, and verifying sensitive communications.
      </p>

      <!-- Certificate Card -->
      <div class="certificate-container" id="printableCertificate">
        <div class="certificate-header">PHISHGUARD CYBERSECURITY ACCREDITATION</div>
        <h2 class="certificate-title">Certificate of Phishing Awareness</h2>
        <p style="color: #94A3B8; font-size: 0.95rem; margin-bottom: 16px;">This credential affirms that</p>
        <div class="certificate-name">${escapeHtml(studentName)}</div>
        <p style="color: #CBD5E1; font-size: 0.95rem; max-width: 540px; margin: 0 auto 24px auto; line-height: 1.6;">
          has demonstrated rigorous comprehension of phishing heuristics, social engineering vector recognition, and digital threat countermeasures with an assessment score of <strong>${percentage}%</strong>.
        </p>
        <div class="certificate-meta-row">
          <div>
            <div style="color: #fff; font-weight: 700;">Issue Date</div>
            <div>${today}</div>
          </div>
          <div>
            <div style="color: #fff; font-weight: 700;">Mentor</div>
            <div>Jagruti Raut</div>
          </div>
          <div>
            <div style="color: #fff; font-weight: 700;">Credential ID</div>
            <div style="font-family: var(--font-mono); color: var(--cyan-accent);">PG-2026-${Math.floor(100000 + Math.random() * 900000)}</div>
          </div>
        </div>
      </div>

      <div style="display: flex; justify-content: center; gap: 16px; margin-top: 28px; flex-wrap: wrap;">
        <button class="btn btn-accent" onclick="window.print()">
          Print / Save Certificate
        </button>
        <button class="btn btn-outline" onclick="location.reload()">
          Retake Assessment
        </button>
        <a href="/dashboard" class="btn btn-primary">
          Return to Dashboard
        </a>
      </div>
    </div>
  `;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}
