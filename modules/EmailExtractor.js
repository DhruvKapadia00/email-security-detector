export class EmailExtractor {
  constructor() {
    this.emailClient = this.detectEmailClient();
    this.maxAttempts = 2;
    this.retryDelay = 200;
  }

  detectEmailClient() {
    const url = window.location.href;
    if (url.includes('mail.google.com')) return 'gmail';
    if (url.includes('outlook.')) return 'outlook';
    if (url.includes('mail.yahoo.com')) return 'yahoo';
    return null;
  }

  // ... rest of the EmailExtractor class methods
}
