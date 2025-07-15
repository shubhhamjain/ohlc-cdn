// Enhanced Security Interceptor - Add this to your cdn.html
// This completely hides your worker URLs from browser network logs

(function() {
    'use strict';
    
    // URLs that should be completely hidden from users
    const HIDDEN_PATTERNS = [
        /cryptograph-oneoff\.shubhham-jain\.workers\.dev/,
        /validatekey\.shubhham-jain\.workers\.dev/,
        /\.r2\.cloudflarestorage\.com/,
        /workers\.dev/,
        /signed.*url/i,
        /validatekey/i,
        /cryptograph/i
    ];
    
    // Store original functions
    const originalFetch = window.fetch;
    const originalXHR = window.XMLHttpRequest;
    const originalURL = window.URL;
    const originalConsole = { ...console };
    
    // Counter for PDF access attempts
    let pdfAccessCount = 0;
    const MAX_PDF_ACCESS = 3;
    
    // Session monitoring
    let sessionStart = Date.now();
    let lastActivity = Date.now();
    const MAX_SESSION_TIME = 30 * 60 * 1000; // 30 minutes
    const MAX_INACTIVITY_TIME = 10 * 60 * 1000; // 10 minutes
    
    // Enhanced fetch interceptor
    window.fetch = function(url, options = {}) {
        const urlString = typeof url === 'string' ? url : url.toString();
        
        // Block direct access to your worker URLs
        if (HIDDEN_PATTERNS.some(pattern => pattern.test(urlString))) {
            console.warn('Direct worker access blocked');
            return Promise.reject(new Error('Access denied to protected resource'));
        }
        
        // Log PDF requests for monitoring
        if (urlString.includes('.pdf') || urlString.includes('/pdf/')) {
            pdfAccessCount++;
            console.log(`PDF access attempt ${pdfAccessCount}`);
            
            // Limit PDF access attempts
            if (pdfAccessCount > MAX_PDF_ACCESS) {
                console.warn('Too many PDF access attempts');
                return Promise.reject(new Error('Access limit exceeded'));
            }
        }
        
        // Add security headers
        options.headers = {
            ...options.headers,
            'X-PDF-Viewer': 'secure',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
        };
        
        return originalFetch.call(this, url, options);
    };
    
    // Enhanced XMLHttpRequest interceptor
    window.XMLHttpRequest = function() {
        const xhr = new originalXHR();
        
        const originalOpen = xhr.open;
        xhr.open = function(method, url, ...args) {
            const urlString = typeof url === 'string' ? url : url.toString();
            
            // Block worker URLs
            if (HIDDEN_PATTERNS.some(pattern => pattern.test(urlString))) {
                console.warn('XHR worker access blocked');
                throw new Error('Access denied to protected resource');
            }
            
            return originalOpen.apply(this, [method, url, ...args]);
        };
        
        const originalSend = xhr.send;
        xhr.send = function(data) {
            xhr.setRequestHeader('X-PDF-Viewer', 'secure');
            xhr.setRequestHeader('Cache-Control', 'no-cache');
            return originalSend.call(this, data);
        };
        
        return xhr;
    };
    
    // URL constructor override to hide sensitive URLs
    window.URL = function(url, base) {
        const urlObj = new originalURL(url, base);
        
        // Override toString to hide sensitive information
        const originalToString = urlObj.toString;
        urlObj.toString = function() {
            let urlStr = originalToString.call(this);
            
            // Replace worker URLs with generic ones
            HIDDEN_PATTERNS.forEach(pattern => {
                if (pattern.test(urlStr)) {
                    urlStr = urlStr.replace(pattern, 'secure-document-service.local');
                }
            });
            
            // Hide tokens and sensitive parameters
            urlStr = urlStr.replace(/token=[^&\s]+/g, 'token=***');
            urlStr = urlStr.replace(/expires=[^&\s]+/g, 'expires=***');
            urlStr = urlStr.replace(/file=[^&\s]+/g, 'file=***');
            
            return urlStr;
        };
        
        // Hide href property
        Object.defineProperty(urlObj, 'href', {
            get: function() {
                return this.toString();
            },
            set: function(value) {
                // Block setting sensitive URLs
                if (HIDDEN_PATTERNS.some(pattern => pattern.test(value))) {
                    console.warn('Blocked attempt to set sensitive URL');
                    return;
                }
                originalURL.prototype.href = value;
            }
        });
        
        return urlObj;
    };
    
    // Enhanced console filtering
    ['log', 'warn', 'error', 'info', 'debug', 'trace'].forEach(method => {
        console[method] = function(...args) {
            const filteredArgs = args.map(arg => {
                if (typeof arg === 'string') {
                    let filtered = arg;
                    
                    // Hide worker URLs
                    HIDDEN_PATTERNS.forEach(pattern => {
                        if (pattern.test(filtered)) {
                            filtered = filtered.replace(pattern, '[PROTECTED]');
                        }
                    });
                    
                    // Hide tokens and sensitive data
                    filtered = filtered.replace(/token=[^&\s]+/g, 'token=***');
                    filtered = filtered.replace(/expires=[^&\s]+/g, 'expires=***');
                    filtered = filtered.replace(/signed.*url/gi, 'signed-url=***');
                    
                    return filtered;
                }
                return arg;
            });
            
            return originalConsole[method].apply(this, filteredArgs);
        };
    });
    
    // Block access to global objects that might expose URLs
    if (typeof window !== 'undefined') {
        Object.defineProperty(window, 'PDFViewerApplication', {
            get: function() {
                return this._pdfViewerApp;
            },
            set: function(value) {
                if (value && typeof value === 'object') {
                    // Hide the URL property
                    if (value.url) {
                        Object.defineProperty(value, 'url', {
                            get: function() {
                                return 'secure-document.pdf';
                            },
                            set: function(newUrl) {
                                // Only allow clean URLs
                                if (!HIDDEN_PATTERNS.some(pattern => pattern.test(newUrl))) {
                                    this._actualUrl = newUrl;
                                }
                            }
                        });
                    }
                    
                    // Hide other sensitive properties
                    ['loadingTask', 'pdfDocument', 'pdfLoadingTask'].forEach(prop => {
                        if (value[prop]) {
                            const originalProp = value[prop];
                            Object.defineProperty(value, prop, {
                                get: function() {
                                    return originalProp;
                                },
                                set: function(newValue) {
                                    // Filter sensitive data
                                    if (newValue && typeof newValue === 'object' && newValue.url) {
                                        if (HIDDEN_PATTERNS.some(pattern => pattern.test(newValue.url))) {
                                            console.warn('Blocked sensitive URL in PDF task');
                                            return;
                                        }
                                    }
                                    originalProp = newValue;
                                }
                            });
                        }
                    });
                }
                this._pdfViewerApp = value;
            }
        });
    }
    
    // Location property protection
    const locationProps = ['href', 'search', 'pathname', 'hash'];
    locationProps.forEach(prop => {
        const originalDescriptor = Object.getOwnPropertyDescriptor(Location.prototype, prop);
        if (originalDescriptor) {
            Object.defineProperty(Location.prototype, prop, {
                get: function() {
                    let value = originalDescriptor.get.call(this);
                    
                    if (typeof value === 'string') {
                        // Hide worker URLs
                        HIDDEN_PATTERNS.forEach(pattern => {
                            if (pattern.test(value)) {
                                value = value.replace(pattern, 'secure-service.local');
                            }
                        });
                        
                        // Hide tokens
                        value = value.replace(/token=[^&]+/g, 'token=***');
                        value = value.replace(/expires=[^&]+/g, 'expires=***');
                    }
                    
                    return value;
                },
                set: originalDescriptor.set
            });
        }
    });
    
    // History API protection
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function(state, title, url) {
        if (url && HIDDEN_PATTERNS.some(pattern => pattern.test(url))) {
            console.warn('Blocked history manipulation with sensitive URL');
            return;
        }
        return originalPushState.call(this, state, title, url);
    };
    
    history.replaceState = function(state, title, url) {
        if (url && HIDDEN_PATTERNS.some(pattern => pattern.test(url))) {
            console.warn('Blocked history manipulation with sensitive URL');
            return;
        }
        return originalReplaceState.call(this, state, title, url);
    };
    
    // Activity tracking
    ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(event => {
        document.addEventListener(event, function() {
            lastActivity = Date.now();
        }, true);
    });
    
    // Session monitoring
    setInterval(function() {
        const now = Date.now();
        const sessionAge = now - sessionStart;
        const inactivityTime = now - lastActivity;
        
        if (sessionAge > MAX_SESSION_TIME) {
            document.body.innerHTML = `
                <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif; background: #f5f5f5;">
                    <h2 style="color: #d32f2f;">Session Expired</h2>
                    <p>Maximum session time exceeded. Please refresh to continue.</p>
                </div>
            `;
        } else if (inactivityTime > MAX_INACTIVITY_TIME) {
            document.body.innerHTML = `
                <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif; background: #f5f5f5;">
                    <h2 style="color: #d32f2f;">Session Inactive</h2>
                    <p>Session expired due to inactivity. Please refresh to continue.</p>
                </div>
            `;
        }
    }, 60000); // Check every minute
    
    // DOM content filtering
    function filterDOMContent() {
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );
        
        let node;
        while (node = walker.nextNode()) {
            if (node.nodeValue && typeof node.nodeValue === 'string') {
                let text = node.nodeValue;
                
                // Hide worker URLs in text content
                HIDDEN_PATTERNS.forEach(pattern => {
                    if (pattern.test(text)) {
                        text = text.replace(pattern, '[PROTECTED]');
                    }
                });
                
                // Hide tokens
                text = text.replace(/token=[^&\s]+/g, 'token=***');
                text = text.replace(/expires=[^&\s]+/g, 'expires=***');
                
                if (text !== node.nodeValue) {
                    node.nodeValue = text;
                }
            }
        }
    }
    
    // Apply DOM filtering when content loads
    document.addEventListener('DOMContentLoaded', filterDOMContent);
    
    // Monitor for dynamically added content
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList' || mutation.type === 'characterData') {
                filterDOMContent();
            }
        });
    });
    
    observer.observe(document.body || document.documentElement, {
        childList: true,
        subtree: true,
        characterData: true
    });
    
    // Prevent common bypass techniques
    Object.defineProperty(window, 'originalFetch', {
        value: undefined,
        writable: false,
        configurable: false
    });
    
    Object.defineProperty(window, 'originalXHR', {
        value: undefined,
        writable: false,
        configurable: false
    });
    
    console.log('PDF Security Interceptor initialized - Worker URLs are now hidden');
})();