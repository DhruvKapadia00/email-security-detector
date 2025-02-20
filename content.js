// Content script initialization
console.log('Content script loaded');

class EmailExtractor {
  async extractEmailData() {
    try {
      const emailClient = this.detectEmailClient();
      console.log('Detected email client:', emailClient);

      let emailData;
      switch (emailClient) {
        case 'gmail':
          emailData = await this.extractGmailData();
          break;
        case 'outlook':
          emailData = await this.extractOutlookData();
          break;
        default:
          throw new Error('Unsupported email client');
      }

      console.log('Extracted email data:', emailData);
      return emailData;
    } catch (error) {
      console.error('Error extracting email data:', error);
      throw error;
    }
  }

  detectEmailClient() {
    const url = window.location.href;
    if (url.includes('mail.google.com')) return 'gmail';
    if (url.includes('outlook.')) return 'outlook';
    return 'unknown';
  }

  async extractGmailData() {
    const emailContainer = document.querySelector('div[role="main"]');
    if (!emailContainer) {
      throw new Error('No email container found. Please make sure an email is open.');
    }

    const messageContainer = emailContainer.querySelector('div[data-message-id]');
    if (!messageContainer) {
      throw new Error('No email message found. Please make sure an email is open.');
    }

    return {
      sender: await this.getGmailSender(messageContainer),
      subject: this.getGmailSubject(messageContainer),
      body: this.getGmailBody(messageContainer),
      links: this.getGmailLinks(messageContainer),
      securityWarnings: this.getGmailWarnings(messageContainer),
      clientWarning: this.getGmailClientWarning(messageContainer),
      hasDisabledAttachments: this.checkGmailDisabledAttachments(messageContainer)
    };
  }

  async extractOutlookData() {
    // Try different Outlook container selectors
    const emailContainer = 
      document.querySelector('[role="main"]') ||
      document.querySelector('.ReadingPaneContent') ||
      document.querySelector('[data-app-section="ReadingPane"]');

    if (!emailContainer) {
      throw new Error('No email container found. Please make sure an email is open.');
    }

    // For Outlook, the message container could be the reading pane itself
    const messageContainer = 
      emailContainer.querySelector('[role="document"]') ||
      emailContainer.querySelector('.allowTextSelection') ||
      emailContainer;

    if (!messageContainer) {
      throw new Error('No email message found. Please make sure an email is open.');
    }

    return {
      sender: this.getOutlookSender(messageContainer),
      subject: this.getOutlookSubject(messageContainer),
      body: this.getOutlookBody(messageContainer),
      links: this.getOutlookLinks(messageContainer),
      securityWarnings: this.getOutlookWarnings(messageContainer),
      clientWarning: this.getOutlookClientWarning(messageContainer),
      hasDisabledAttachments: this.checkOutlookDisabledAttachments(messageContainer)
    };
  }

  // Gmail methods
  getGmailSender(container) {
    const senderElement = container.querySelector('[email], .gD');
    return senderElement ? senderElement.getAttribute('email') || senderElement.textContent.trim() : '';
  }

  getGmailSubject(container) {
    const subjectElement = container.querySelector('h2, .hP');
    return subjectElement ? subjectElement.textContent.trim() : '';
  }

  getGmailBody(container) {
    const bodyElement = container.querySelector('.a3s.aiL, [role="textbox"]');
    return bodyElement ? bodyElement.textContent.trim() : '';
  }

  getGmailLinks(container) {
    return Array.from(container.querySelectorAll('a[href]'))
      .map(link => ({
        href: link.href,
        text: link.textContent.trim()
      }))
      .filter(link => link.href && !link.href.startsWith('mailto:'));
  }

  getGmailWarnings(container) {
    const warnings = [];
    const warningElements = container.querySelectorAll('.h7, [role="alert"]');
    
    warningElements.forEach(element => {
      const text = element.textContent.trim();
      let severity = 'medium';
      
      if (text.includes('suspicious') || text.includes('warning')) {
        severity = 'high';
      } else if (text.includes('danger') || text.includes('critical')) {
        severity = 'critical';
      }
      
      warnings.push({ text, severity });
    });
    
    return warnings;
  }

  getGmailClientWarning(container) {
    const warningElement = container.querySelector('.spam-warning, .phishing-warning');
    if (!warningElement) return null;

    const text = warningElement.textContent.trim();
    let type = 'suspicious';

    if (text.includes('dangerous') || text.includes('malware')) {
      type = 'dangerous';
    }

    return { text, type };
  }

  checkGmailDisabledAttachments(container) {
    return container.querySelector('.blocked-attachment, .disabled-attachment') !== null;
  }

  // Outlook methods
  getOutlookSender(container) {
    const senderElement = 
      container.querySelector('[data-automation-id="FromContainer"]') ||
      container.querySelector('.from, .uQnxL') ||
      container.querySelector('[aria-label*="From"]');
    return senderElement ? senderElement.textContent.trim() : '';
  }

  getOutlookSubject(container) {
    const subjectElement = 
      container.querySelector('[data-automation-id="SubjectLine"]') ||
      container.querySelector('.subjectLine, ._2LBcC') ||
      container.querySelector('[role="heading"]');
    return subjectElement ? subjectElement.textContent.trim() : '';
  }

  getOutlookBody(container) {
    const bodyElement = 
      container.querySelector('[data-automation-id="MessageBody"]') ||
      container.querySelector('.message-body, ._1hHMg') ||
      container.querySelector('[role="document"]');
    return bodyElement ? bodyElement.textContent.trim() : '';
  }

  getOutlookLinks(container) {
    return Array.from(container.querySelectorAll('a[href]'))
      .map(link => ({
        href: link.href,
        text: link.textContent.trim()
      }))
      .filter(link => link.href && !link.href.startsWith('mailto:'));
  }

  getOutlookWarnings(container) {
    const warnings = [];
    const warningElements = container.querySelectorAll(
      '.ms-MessageHeader-securityStatus, ' +
      '.ms-MessageHeader-warning, ' +
      '[role="alert"]'
    );
    
    warningElements.forEach(element => {
      const text = element.textContent.trim();
      let severity = 'medium';
      
      if (text.includes('suspicious') || text.includes('warning')) {
        severity = 'high';
      } else if (text.includes('danger') || text.includes('critical')) {
        severity = 'critical';
      }
      
      warnings.push({ text, severity });
    });
    
    return warnings;
  }

  getOutlookClientWarning(container) {
    const warningElement = container.querySelector(
      '.ms-MessageHeader-securityStatus, ' +
      '.ms-MessageHeader-warning, ' +
      '[role="alert"]'
    );
    if (!warningElement) return null;

    const text = warningElement.textContent.trim();
    let type = 'suspicious';

    if (text.includes('dangerous') || text.includes('malware')) {
      type = 'dangerous';
    }

    return { text, type };
  }

  checkOutlookDisabledAttachments(container) {
    return container.querySelector(
      '.ms-MessageHeader-blockedAttachment, ' +
      '.ms-MessageHeader-disabledAttachment, ' +
      '[aria-label*="blocked attachment"]'
    ) !== null;
  }
}

// Initialize message listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Received message:', request);
  
  if (request.action === 'extractEmailData') {
    console.log('Extracting email data...');
    const extractor = new EmailExtractor();
    
    extractor.extractEmailData()
      .then(data => {
        console.log('Successfully extracted email data:', data);
        sendResponse({ success: true, data });
      })
      .catch(error => {
        console.error('Failed to extract email data:', error);
        sendResponse({ 
          success: false, 
          error: error.message || 'Failed to extract email data. Please make sure an email is open and try again.' 
        });
      });
    
    return true; // Required for async response
  }
});
