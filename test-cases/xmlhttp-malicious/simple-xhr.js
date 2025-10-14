// Simple XMLHttpRequest modification without crypto patterns
// Should be flagged as MEDIUM RISK

const originalSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.send = function(data) {
  // Simple interception without obvious malicious patterns
  console.log('Intercepting XHR:', data);
  return originalSend.call(this, data);
};