class EmailAnalyzer {
  constructor() {
    this.analyzeButton = document.getElementById('analyze-btn');
    this.loadingElement = document.getElementById('loading');
    this.errorElement = document.getElementById('error-message');
    this.resultsElement = document.getElementById('analysis-results');
    
    this.analyzeButton.addEventListener('click', () => this.analyzeEmail());
    this.setupUI();
  }

  setupUI() {
    this.hideLoading();
    this.hideError();
    this.hideResults();
  }

  showLoading() {
    this.loadingElement.classList.remove('hidden');
    this.analyzeButton.disabled = true;
  }

  hideLoading() {
    this.loadingElement.classList.add('hidden');
    this.analyzeButton.disabled = false;
  }

  showError(message) {
    this.errorElement.textContent = message;
    this.errorElement.classList.remove('hidden');
  }

  hideError() {
    this.errorElement.classList.add('hidden');
  }

  showResults() {
    this.resultsElement.classList.remove('hidden');
  }

  hideResults() {
    this.resultsElement.classList.add('hidden');
  }

  async analyzeEmail() {
    this.hideError();
    this.hideResults();
    this.showLoading();

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (!tab) {
        throw new Error('No active tab found');
      }

      // Check if we're on a supported email client
      const supportedDomains = [
        'mail.google.com',
        'outlook.live.com',
        'outlook.office.com',
        'outlook.office365.com'
      ];

      if (!supportedDomains.some(domain => tab.url.includes(domain))) {
        throw new Error('Please open this extension while viewing an email in Gmail or Outlook.');
      }

      // Inject content script if not already injected
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => true
        });
      } catch (error) {
        console.error('Script injection error:', error);
        throw new Error('Unable to access the email page. Please refresh and try again.');
      }

      // Send message to content script
      try {
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'extractEmailData' });
        if (!response.success) {
          throw new Error(response.error || 'Failed to analyze email');
        }

        const emailData = response.data;
        this.updateUI(this.analyzeEmailData(emailData));
        this.showResults();
      } catch (error) {
        if (error.message.includes('Receiving end does not exist')) {
          throw new Error('Please refresh the email page and try again.');
        }
        throw error;
      }
    } catch (error) {
      this.showError(error.message || 'An error occurred while analyzing the email');
    } finally {
      this.hideLoading();
    }
  }

  analyzeEmailData(emailData) {
    // Basic risk assessment
    let score = 0;
    const flags = [];

    // Check security warnings
    if (emailData.securityWarnings && emailData.securityWarnings.length > 0) {
      score += 50;
      flags.push(...emailData.securityWarnings.map(w => w.text));
    }

    // Check for suspicious links
    if (emailData.links) {
      const suspiciousLinkCount = emailData.links.filter(link => {
        const url = new URL(link.href);
        return url.protocol === 'http:' || // Non-HTTPS
               url.hostname.includes('ip') || // IP address
               url.hostname.length > 30; // Unusually long domain
      }).length;

      if (suspiciousLinkCount > 0) {
        score += suspiciousLinkCount * 10;
        flags.push(`Found ${suspiciousLinkCount} suspicious link(s)`);
      }
    }

    // Check client warnings
    if (emailData.clientWarning) {
      score += 30;
      flags.push(emailData.clientWarning.text);
    }

    return {
      score: Math.min(100, score),
      flags: flags
    };
  }

  updateUI(results) {
    const riskScore = document.getElementById('risk-score');
    const riskLevel = document.getElementById('risk-level');
    const warningsList = document.getElementById('warnings-list');

    // Update risk score
    riskScore.textContent = Math.round(results.score);

    // Update risk level
    let level = 'Low';
    if (results.score >= 80) {
      level = 'High';
    } else if (results.score >= 40) {
      level = 'Medium';
    }
    riskLevel.textContent = level;
    riskLevel.className = `risk-level-${level.toLowerCase()}`; // Add color class

    // Update warnings
    warningsList.innerHTML = '';
    if (results.flags && results.flags.length > 0) {
      results.flags.forEach(warning => {
        const li = document.createElement('li');
        li.textContent = warning;
        warningsList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.textContent = 'No specific warnings found';
      warningsList.appendChild(li);
    }
  }
}

// Initialize the analyzer when the popup loads
document.addEventListener('DOMContentLoaded', () => {
  new EmailAnalyzer();
});
