/* ==========================================================================
   PHISHGUARD - Email Threat Analyzer Interactive Engine
   Sample Email Loaders & Visual Preview
   ========================================================================== */

const EMAIL_SAMPLES = {
  urgent_bank: {
    sender: 'Bank of America Alerts <security-notice@boa-verify-online92.xyz>',
    subject: 'URGENT: Unauthorized Sign-in Attempt - Action Required Within 24 Hours',
    body: `Dear Customer,

We detected an unrecognized login attempt to your online banking portal from an unauthorized IP address in Frankfurt, Germany.

To safeguard your funds and protect against fraudulent transactions, your checking and savings accounts have been temporarily locked.

Please verify your credentials immediately using our secure verification terminal:
http://boa-login-verify-account.xyz/auth?user=secure

Failure to confirm your account identity within 24 hours will result in permanent suspension of online wire transfer capabilities.

Sincerely,
Fraud Prevention Department
Bank of America Security Operations`
  },
  ceo_giftcard: {
    sender: 'Michael Roberts <mroberts.executive@gmail.com>',
    subject: 'Quick task - Need your assistance right now',
    body: `Hi,

Are you currently at your desk? I am currently tied up in an urgent executive board meeting with our external partners and cannot take phone calls right now.

I need you to urgently purchase 5 Apple Gift Cards ($100 each) for an employee recognition presentation this afternoon. Please scratch the back, take clear photos of the codes and serial numbers, and email them back to me directly as soon as possible.

I will have accounting process an expense reimbursement check for you first thing tomorrow morning. Treat this with high discretion.

Thanks,
Michael Roberts
Chief Executive Officer`
  },
  safe_collaboration: {
    sender: 'GitHub Notifications <notifications@github.com>',
    subject: '[GitHub] Chauhan Brijesh Ramayan requested a pull request review on repo/phishguard',
    body: `Hello Brijesh,

A new pull request #14 ("Add heuristic risk scoring engine for phishing detection") has been opened on your repository.

Author: Chauhan Brijesh Ramayan
Branch: feature/cyber-heuristics -> main

To review code diffs and submit feedback, visit:
https://github.com/phishguard-project/security-core/pull/14

You are receiving this email because you are watching this repository.
Manage your email notification preferences at https://github.com/settings/notifications`
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const senderInput = document.getElementById('emailSenderInput');
  const subjectInput = document.getElementById('emailSubjectInput');
  const bodyInput = document.getElementById('emailBodyInput');

  const sampleButtons = document.querySelectorAll('.load-sample-btn');

  sampleButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleKey = btn.getAttribute('data-sample');
      const data = EMAIL_SAMPLES[sampleKey];
      if (data && senderInput && subjectInput && bodyInput) {
        senderInput.value = data.sender;
        subjectInput.value = data.subject;
        bodyInput.value = data.body;

        // Visual flash to indicate sample loaded
        [senderInput, subjectInput, bodyInput].forEach(el => {
          el.style.backgroundColor = '#EFF6FF';
          setTimeout(() => el.style.backgroundColor = '', 300);
        });
      }
    });
  });
});
