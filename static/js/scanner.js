/* ==========================================================================
   PHISHGUARD - URL Scanner Interactive Engine & Radial Meter Animation
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Radial Meter Animation
  const arcElement = document.querySelector('.circle-arc');
  const scoreElement = document.getElementById('gaugeScore');

  if (arcElement && scoreElement) {
    const targetScore = parseInt(scoreElement.getAttribute('data-score') || '0', 10);
    let currentScore = 0;
    
    // Set color class
    if (targetScore >= 70) {
      arcElement.classList.add('stroke-danger');
    } else if (targetScore >= 35) {
      arcElement.classList.add('stroke-warning');
    } else {
      arcElement.classList.add('stroke-success');
    }

    // Animate arc stroke and number
    setTimeout(() => {
      arcElement.setAttribute('stroke-dasharray', `${targetScore}, 100`);
    }, 150);

    const duration = 1200; // ms
    const stepTime = Math.max(10, Math.floor(duration / (targetScore || 1)));
    const timer = setInterval(() => {
      if (currentScore >= targetScore) {
        clearInterval(timer);
        scoreElement.textContent = targetScore;
      } else {
        currentScore++;
        scoreElement.textContent = currentScore;
      }
    }, stepTime);
  }

  // 2. Preset Quick Chips Populator
  const quickChips = document.querySelectorAll('.quick-chip');
  const urlInputs = document.querySelectorAll('input[name="url"], #previewUrlInput');

  quickChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const sampleUrl = chip.getAttribute('data-url');
      if (sampleUrl) {
        urlInputs.forEach(input => {
          input.value = sampleUrl;
          input.focus();
        });

        // If on landing page preview, trigger live client-side preview update
        if (typeof updateLandingPreview === 'function') {
          updateLandingPreview(sampleUrl);
        }
      }
    });
  });

  // 3. Live Scanner Preview on Landing Page
  const previewInput = document.getElementById('previewUrlInput');
  const previewAnalyzeBtn = document.getElementById('previewAnalyzeBtn');

  if (previewInput && previewAnalyzeBtn) {
    previewAnalyzeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const val = previewInput.value.trim();
      if (!val) return;
      // Perform live AJAX update right on page, and user can also click Inspect for full page
      updateLandingPreview(val);
    });
  }
});

// Live AJAX Telemetry Update for Landing Page
function updateLandingPreview(url) {
  const scoreNum = document.querySelector('.preview-score-num');
  const scoreBadge = document.querySelector('.preview-score-pane .badge');
  const checksGrid = document.querySelector('.preview-checks-grid');

  if (!scoreNum || !url) return;

  scoreNum.textContent = '...';
  if (scoreBadge) scoreBadge.textContent = 'SCANNING...';

  fetch('/api/scan/url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    if (data.error) return;

    // Update score number
    scoreNum.textContent = data.risk_score;
    if (data.risk_score >= 70) {
      scoreNum.style.color = '#EF4444';
    } else if (data.risk_score >= 35) {
      scoreNum.style.color = '#F59E0B';
    } else {
      scoreNum.style.color = '#10B981';
    }

    // Update classification badge
    if (scoreBadge) {
      scoreBadge.className = `badge badge-${data.risk_badge}`;
      scoreBadge.textContent = data.risk_level;
    }

    // Update checks grid
    if (checksGrid) {
      const items = [];
      data.passed_checks.slice(0, 3).forEach(c => {
        items.push(`
          <div class="preview-check-pill">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>${c.name}</span>
          </div>
        `);
      });

      data.potential_concerns.slice(0, 3).forEach(c => {
        items.push(`
          <div class="preview-check-pill" style="color: ${c.status === 'danger' ? '#EF4444' : '#F59E0B'};">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <span>${c.name}</span>
          </div>
        `);
      });

      checksGrid.innerHTML = items.join('');
    }
  })
  .catch(err => {
    console.log('Telemetry scan error:', err);
  });
}
