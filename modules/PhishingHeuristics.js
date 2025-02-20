export class PhishingHeuristics {
  constructor() {
    // Initialize trusted domains by category
    this.trustedDomains = new Set([
      // Email Providers
      'gmail.com',
      'yahoo.com',
      'outlook.com',
      'hotmail.com',
      'aol.com',
      'icloud.com',
      'mail.com',
      'msn.com',
      'live.com',
      'zoho.com',
      'yandex.com',
      'protonmail.com',
      'gmx.com',
      'fastmail.com',
      'hushmail.com',
      'inbox.com',
      'rediffmail.com',
      'lycos.com',
      'rocketmail.com',

      // Social Media
      'facebookmail.com',
      'twitter.com',
      'linkedin.com',
      'instagram.com',
      'pinterest.com',
      'snapchat.com',
      'tiktok.com',
      'reddit.com',

      // E-commerce
      'amazon.com',
      'ebay.com',
      'walmart.com',
      'target.com',
      'bestbuy.com',
      'costco.com',
      'etsy.com',

      // Tech Companies
      'apple.com',
      'microsoft.com',
      'google.com',
      'amazonaws.com',
      'salesforce.com',
      'oracle.com',
      'ibm.com',
      'intel.com',
      'dell.com',
      'hp.com',
      'adobe.com',

      // Entertainment
      'netflix.com',
      'spotify.com',
      'pandora.com',
      'hulu.com',

      // Travel & Transportation
      'uber.com',
      'lyft.com',
      'airbnb.com',
      'booking.com',
      'expedia.com',
      'tripadvisor.com',

      // Shipping
      'fedex.com',
      'ups.com',
      'dhl.com',

      // Payment & Financial
      'paypal.com',
      'stripe.com',
      'squareup.com',
      'shopify.com',
      'chase.com',
      'bankofamerica.com',
      'wellsfargo.com',
      'citibank.com',
      'usbank.com',
      'pnc.com',

      // Cloud & Collaboration
      'dropbox.com',
      'box.com',
      'slack.com',
      'zoom.us',
      'gitlab.com',
      'github.com',

      // News & Media
      'cnn.com',
      'bbc.com',
      'nytimes.com',
      'washingtonpost.com',
      'forbes.com',
      'bloomberg.com',

      // Development & Tech
      'stackoverflow.com',
      'medium.com',
      'wordpress.com',
      'blogger.com',
      'tumblr.com',
      'squarespace.com',

      // International
      't-online.de',
      'libero.it',
      'terra.com.br',
      'rambler.ru',
      'vk.com',
      'qq.com',
      'sina.com.cn',
      '163.com',
      '126.com',
      'sohu.com',
      'mail.ru',
      'orange.fr',
      'btinternet.com',
      'cox.net'
    ]);

    // Phishing indicators
    this.suspiciousWords = new Set([
      'verify', 'confirm', 'validate', 'login', 'sign in', 'click here',
      'account', 'suspended', 'unusual activity', 'security', 'unauthorized',
      'password', 'credit card', 'ssn', 'social security', 'banking',
      'urgent', 'immediate', 'action required', 'expire', 'terminated',
      'limited time', 'offer', 'won', 'winner', 'prize', 'claim',
      'inheritance', 'payment', 'transfer', 'transaction', 'access',
      'update required', 'account access', 'unusual sign in', 'verify identity',
      'security update', 'suspicious activity', 'account alert'
    ]);

    this.urgentPhrases = new Set([
      'immediate action', 'urgent action', 'account suspended',
      'unusual activity', 'security alert', 'unauthorized access',
      'account blocked', 'account limited', 'verify now',
      'expires today', 'final notice', 'final warning',
      'immediate verification', 'suspicious login',
      'account compromised', 'security breach'
    ]);

    this.spamTriggers = new Set([
      'million dollars', 'nigerian prince', 'lottery winner',
      'claim your prize', 'wire transfer', 'bank transfer',
      'western union', 'money transfer', 'inheritance claim',
      'unclaimed funds', 'winning notification', 'award winning',
      'congratulations you won', 'beneficiary', 'next of kin'
    ]);

    // Scoring weights
    this.weights = {
      untrustedDomain: 30,
      suspiciousWords: 5,
      urgentPhrases: 10,
      spamTriggers: 15,
      clientWarning: 25,
      suspiciousLink: 10,
      mismatchedLink: 20,
      excessiveLinks: 15,
      personalInfoRequest: 20,
      poorFormatting: 5,
      genericGreeting: 5
    };
  }

  analyzeEmail(emailData) {
    let riskScore = 0;
    const flags = [];

    // Fast domain check
    const senderDomain = this.extractDomain(emailData.sender);
    const isTrustedDomain = this.trustedDomains.has(senderDomain);
    
    if (!isTrustedDomain) {
      riskScore += this.weights.untrustedDomain;
      flags.push('Sender domain is not in trusted list');
    }

    // Quick text analysis (combine subject and body for single pass)
    const fullText = `${emailData.subject} ${emailData.body}`.toLowerCase();
    
    // Check for suspicious words (single pass)
    const foundSuspiciousWords = new Set();
    for (const word of this.suspiciousWords) {
      if (fullText.includes(word)) {
        foundSuspiciousWords.add(word);
      }
    }
    
    if (foundSuspiciousWords.size > 0) {
      riskScore += Math.min(foundSuspiciousWords.size * this.weights.suspiciousWords, 30);
      flags.push(`Contains suspicious words: ${Array.from(foundSuspiciousWords).slice(0, 3).join(', ')}`);
    }

    // Check for urgent phrases (single pass)
    const foundUrgentPhrases = new Set();
    for (const phrase of this.urgentPhrases) {
      if (fullText.includes(phrase)) {
        foundUrgentPhrases.add(phrase);
      }
    }

    if (foundUrgentPhrases.size > 0) {
      riskScore += Math.min(foundUrgentPhrases.size * this.weights.urgentPhrases, 30);
      flags.push('Contains urgent or threatening language');
    }

    // Quick spam trigger check
    for (const trigger of this.spamTriggers) {
      if (fullText.includes(trigger)) {
        riskScore += this.weights.spamTriggers;
        flags.push('Contains common spam phrases');
        break; // One is enough
      }
    }

    // Fast link analysis
    if (emailData.links && emailData.links.length > 0) {
      const linkResults = this.analyzeSuspiciousLinks(emailData.links);
      riskScore += linkResults.score;
      flags.push(...linkResults.flags);
    }

    // Check for personal information requests
    if (this.containsPersonalInfoRequest(fullText)) {
      riskScore += this.weights.personalInfoRequest;
      flags.push('Requests personal information');
    }

    // Generic greeting check (fast string check)
    if (this.hasGenericGreeting(emailData.body)) {
      riskScore += this.weights.genericGreeting;
      flags.push('Uses generic greeting');
    }

    // Email client warnings (already fast)
    if (emailData.securityWarnings && emailData.securityWarnings.length > 0) {
      riskScore += this.weights.clientWarning;
      flags.push('Email client detected security concerns');
    }

    // Ensure risk score stays within bounds
    riskScore = Math.min(Math.max(riskScore, 0), 100);

    return {
      score: riskScore,
      flags: flags,
      isTrustedDomain
    };
  }

  containsPersonalInfoRequest(text) {
    const personalInfoPatterns = [
      'ssn', 'social security',
      'credit card', 'card number',
      'banking details', 'bank account',
      'username password', 'login credentials',
      'verify.{0,20}account',
      'confirm.{0,20}identity',
      'update.{0,20}payment'
    ];
    
    // Single regex test for speed
    return new RegExp(personalInfoPatterns.join('|'), 'i').test(text);
  }

  hasGenericGreeting(text) {
    // Fast check for common generic greetings
    const firstLine = text.split('\\n')[0].toLowerCase();
    return /^(dear sir|dear madam|dear user|dear customer|dear email user|to whom it may concern|dear account holder)/i.test(firstLine);
  }

  analyzeSuspiciousLinks(links) {
    let score = 0;
    const flags = [];
    
    // Skip if no links
    if (!links || links.length === 0) return { score: 0, flags: [] };

    // Check for excessive links
    if (links.length > 3) {
      score += this.weights.excessiveLinks;
      flags.push('Unusually high number of links');
    }

    // Fast Set for checking duplicates
    const domains = new Set();
    
    for (const link of links) {
      const domain = this.extractDomain(link.href);
      domains.add(domain);
      
      // Quick trusted domain check
      if (!this.trustedDomains.has(domain)) {
        score += this.weights.suspiciousLink;
        flags.push(`Suspicious link domain: ${domain}`);
      }

      // Check for text/href mismatch (if text contains a URL)
      if (link.text && link.href) {
        const textDomain = this.extractDomain(link.text);
        if (textDomain && textDomain !== domain) {
          score += this.weights.mismatchedLink;
          flags.push('Mismatched link text and destination');
          break; // One mismatch is enough
        }
      }
    }

    return { score, flags };
  }

  extractDomain(text) {
    if (!text) return '';
    // Fast domain extraction using regex
    const match = text.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s]+)/i);
    return match ? match[1].toLowerCase() : '';
  }
}
