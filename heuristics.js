class PhishingHeuristics {
  constructor() {
    // Pre-compile all regular expressions
    this.regexes = {
      ipAddress: /^(\d{1,3}\.){3}\d{1,3}$/,
      unicode: /[\u0080-\uFFFF]/,
      wordBoundary: (phrase) => new RegExp(`\\b${phrase}\\b`, 'i'),
      marketing: /newsletter|subscription|update|announcement|invitation|offer|discount|sale|promotion/i,
      capsSequence: /[A-Z]{5,}/g,
      exclamation: /!/g,
      emoji: /[\u{1F300}-\u{1F9FF}]/gu,
      mixedEncoding: /[\u0080-\u024F\u0400-\u04FF]/g,
      urlInText: /[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/\S*)?/
    };

    this.urlThresholds = {
      maxLength: 100,
      maxDepth: 4,
      suspiciousChars: new Set(['@', '=', '+']),
      urlShorteners: new Set([
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'tiny.cc',
        'is.gd', 'cli.gs', 'pic.gd', 'dwarfurl.com', 'ow.ly',
        'yfrog.com', 'migre.me', 'ff.im', 'tiny.pl', 'url4.eu',
        'tr.im', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
        'short.to', 'budurl.com', 'ping.fm', 'post.ly', 'just.as',
        'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com',
        'tinyurl.com', 'rubyurl.com'
      ]),
      trustedDomains: new Set([
        'linkedin.com',
        'linkedin-ei.com',
        'linkedin-msgs.com',
        'outlook.com',
        'google.com',
        'facebook.com',
        'twitter.com',
        'instagram.com',
        'amazon.com',
        'microsoft.com',
        'apple.com',
        'github.com'
      ]),
      commonTLDs: new Set(['.com', '.org', '.net', '.edu', '.gov']),
      suspiciousTLDs: new Set(['.xyz', '.top', '.club', '.online', '.site', '.work', '.info'])
    };

    this.contentThresholds = {
      urgencyPhrases: [
        'urgent', 'immediate', 'action required', 'account suspended',
        'verify your account', 'security alert', 'unauthorized access',
        'limited time', 'expires soon', 'act now', 'immediate attention',
        'account closed', 'suspicious activity', 'unusual sign-in',
        'password expired', 'security breach', 'unusual activity'
      ],
      sensitiveDataPhrases: [
        'social security', 'password', 'credit card', 'bank account',
        'login credentials', 'verify identity', 'confirm identity',
        'personal details', 'billing information', 'payment info'
      ],
      commonBrands: [
        { name: 'paypal', domain: 'paypal.com' },
        { name: 'apple', domain: 'apple.com' },
        { name: 'microsoft', domain: 'microsoft.com' },
        { name: 'google', domain: 'google.com' },
        { name: 'amazon', domain: 'amazon.com' },
        { name: 'facebook', domain: 'facebook.com' },
        { name: 'netflix', domain: 'netflix.com' },
        { name: 'bank', domains: ['.bank', '.com', '.net'] }
      ],
      grammarMistakes: new Set([
        'kindly', 'dear valued', 'dear costumer', 'dear customer',
        'verify you account', 'your winning', 'you have won',
        'congratulation you', 'won a prize'
      ]),
      marketingPhrases: new Set([
        'unsubscribe',
        'view in browser',
        'privacy policy',
        'terms of service',
        'email preferences',
        'update profile',
        'marketing preferences',
        'subscription preferences'
      ])
    };
  }

  analyzeEmail(emailData) {
    let score = 0;
    const flags = [];

    // Handle null/undefined emailData gracefully
    if (!emailData) {
      return {
        score: 0,
        flags: ['Unable to analyze email: No email data found']
      };
    }

    // Check if sender is from a trusted domain
    const senderDomain = this.extractDomain(emailData.sender || '');
    const isTrustedSender = Array.from(this.urlThresholds.trustedDomains).some(domain => 
      senderDomain.includes(domain)
    );

    // If it's from a trusted domain, lower the base risk
    if (isTrustedSender) {
      score = Math.min(score, 30);
    }

    // Check security warnings from email client
    if (emailData.securityWarnings && emailData.securityWarnings.length > 0) {
      for (const warning of emailData.securityWarnings) {
        // For trusted senders, reduce the severity of warnings
        const severityMultiplier = isTrustedSender ? 0.5 : 1;
        
        switch (warning.severity) {
          case 'critical':
            score = Math.max(score, 85 * severityMultiplier);
            flags.push(`CRITICAL: ${warning.text}`);
            break;
          case 'high':
            score = Math.max(score, 70 * severityMultiplier);
            flags.push(`HIGH RISK: ${warning.text}`);
            break;
          case 'medium':
            score = Math.max(score, 40 * severityMultiplier);
            flags.push(warning.text);
            break;
          default:
            score = Math.max(score, 20 * severityMultiplier);
            flags.push(warning.text);
        }
      }
    }

    // Check if email client has marked it as dangerous
    if (emailData.clientWarning) {
      if (emailData.clientWarning.type === 'dangerous') {
        score += 50;
        flags.push(`Email client warning: ${emailData.clientWarning.text}`);
      } else if (emailData.clientWarning.type === 'suspicious') {
        score += 30;
        flags.push(`Email client warning: ${emailData.clientWarning.text}`);
      } else {
        score += 15;
        flags.push(`Email client warning: ${emailData.clientWarning.text}`);
      }
    }

    // Check for disabled attachments
    if (emailData.hasDisabledAttachments) {
      score += 15;
      flags.push('Email client has disabled attachments due to security concerns');
    }

    // Add content analysis results
    const contentResults = this.analyzeContent(emailData);
    score = Math.max(score, contentResults.score);
    if (contentResults.flags) {
      flags.push(...contentResults.flags);
    }

    // Add sender analysis results
    const senderResults = this.analyzeSender(emailData.sender || '');
    score = Math.max(score, senderResults.score);
    if (senderResults.flags) {
      flags.push(...senderResults.flags);
    }

    // Add URL analysis results if links exist
    if (emailData.links && emailData.links.length > 0) {
      const urlResults = this.analyzeUrls(emailData.links);
      score = Math.max(score, urlResults.score);
      if (urlResults.flags) {
        flags.push(...urlResults.flags);
      }
    }

    // Add behavioral analysis
    const behavioralResults = this.analyzeBehavioral(emailData);
    score = Math.max(score, behavioralResults.score);
    if (behavioralResults.flags) {
      flags.push(...behavioralResults.flags);
    }

    // If it's clearly marketing content, reduce the score
    if (this.isMarketingEmail(emailData)) {
      score = Math.min(score, 30);
      if (score > 0) {
        flags.push('This appears to be a marketing email');
      }
    }

    return {
      score: Math.min(100, score),
      flags: [...new Set(flags.filter(Boolean))] // Remove duplicates and null/undefined values
    };
  }

  isMarketingEmail(emailData) {
    const fullContent = `${emailData.subject} ${emailData.body}`.toLowerCase();
    const marketingPhraseCount = Array.from(this.contentThresholds.marketingPhrases)
      .filter(phrase => fullContent.includes(phrase))
      .length;
    
    return marketingPhraseCount >= 3 || this.regexes.marketing.test(fullContent);
  }

  analyzeUrls(links) {
    let score = 0;
    const flags = new Set();
    const processedUrls = new Set();
    let longUrlCount = 0;

    for (const link of links) {
      if (!link.href || processedUrls.has(link.href)) continue;
      processedUrls.add(link.href);

      try {
        const url = new URL(link.href);
        const displayText = link.text.toLowerCase();
        
        // Quick check for trusted domains
        if (this.urlThresholds.trustedDomains.has(url.hostname)) continue;

        // Length check
        if (url.href.length > this.urlThresholds.maxLength) {
          score += 5;
          longUrlCount++;
          continue;
        }

        // IP address check
        if (this.regexes.ipAddress.test(url.hostname)) {
          score += 25;
          flags.add('IP address used instead of domain name');
        }

        // URL shortener check
        if (this.urlThresholds.urlShorteners.has(url.hostname)) {
          score += 15;
          flags.add('URL shortening service detected');
        }

        // Suspicious TLD check
        const tld = '.' + url.hostname.split('.').pop();
        if (this.urlThresholds.suspiciousTLDs.has(tld)) {
          score += 15;
          flags.add(`Suspicious TLD detected: ${tld}`);
        }

        // Homograph attack check
        if (this.regexes.unicode.test(url.hostname)) {
          score += 25;
          flags.add('Possible homograph attack detected');
        }

      } catch (error) {
        console.error('Error analyzing URL:', error);
      }
    }

    if (longUrlCount > 0) {
      flags.add(`Found ${longUrlCount} unusually long URL${longUrlCount > 1 ? 's' : ''}`);
    }

    return {
      score: Math.min(100, score),
      flags: Array.from(flags)
    };
  }

  analyzeContent(emailData) {
    const fullContent = `${emailData.subject} ${emailData.body}`.toLowerCase();
    let score = 0;
    const flags = new Set();

    // Quick marketing check
    const isMarketing = this.regexes.marketing.test(fullContent);
    const marketingPhraseCount = Array.from(this.contentThresholds.marketingPhrases)
      .filter(phrase => fullContent.includes(phrase))
      .length;

    if (marketingPhraseCount >= 3) {
      return { score: 0, flags: [] }; // Skip further analysis for obvious marketing
    }

    const checks = [
      {
        phrases: this.contentThresholds.urgencyPhrases,
        scorePerMatch: isMarketing ? 5 : 10,
        maxScore: isMarketing ? 15 : 30,
        flagTemplate: count => `Urgent language detected (${count} instances)`
      },
      {
        phrases: this.contentThresholds.sensitiveDataPhrases,
        scorePerMatch: 15,
        maxScore: 35,
        flagTemplate: count => `Requests for sensitive information detected (${count} instances)`
      }
    ];

    for (const check of checks) {
      const matchCount = check.phrases
        .filter(phrase => this.regexes.wordBoundary(phrase).test(fullContent))
        .length;

      if (matchCount > 0) {
        score += Math.min(check.maxScore, matchCount * check.scorePerMatch);
        flags.add(check.flagTemplate(matchCount));
      }
    }

    return {
      score: Math.min(100, score),
      flags: Array.from(flags)
    };
  }

  analyzeSender(sender) {
    if (!sender) return { score: 0, flags: ['Missing sender information'] };

    let score = 0;
    const flags = new Set();
    const senderLower = sender.toLowerCase();

    // Quick checks using Sets for O(1) lookup
    for (const brand of this.contentThresholds.commonBrands) {
      if (senderLower.includes(brand.name) && 
          (brand.domain && !senderLower.includes(brand.domain))) {
        score += 25;
        flags.add(`Potential ${brand.name} impersonation`);
        break;
      }
    }

    return {
      score: Math.min(100, score),
      flags: Array.from(flags)
    };
  }

  analyzeBehavioral(emailData) {
    let score = 0;
    const flags = new Set();

    // Minimal behavioral checks for performance
    if (emailData.body && emailData.body.length < 30) {
      score += 10;
      flags.add('Suspiciously short email content');
    }

    if (emailData.subject) {
      const capsCount = (emailData.subject.match(this.regexes.capsSequence) || []).length;
      if (capsCount > 2) {
        score += Math.min(15, capsCount * 5);
        flags.add('Unusual capitalization detected');
      }
    }

    return {
      score: Math.min(100, score),
      flags: Array.from(flags)
    };
  }

  extractDomain(email) {
    try {
      // Handle different email formats
      let domain = email.toLowerCase();
      
      // Remove any display names
      if (domain.includes('<')) {
        domain = domain.split('<')[1].split('>')[0];
      }
      
      // Extract domain from email
      if (domain.includes('@')) {
        domain = domain.split('@')[1];
      }
      
      return domain;
    } catch (error) {
      console.error('Error extracting domain:', error);
      return '';
    }
  }
}

// Export for use in popup.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishingHeuristics;
} else if (typeof window !== 'undefined') {
  window.PhishingHeuristics = PhishingHeuristics;
}
