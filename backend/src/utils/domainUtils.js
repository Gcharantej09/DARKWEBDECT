function getRootDomain(urlString) {
    try {
      const u = new URL(urlString);
      const parts = u.hostname.split('.');
      if (parts.length <= 2) return u.hostname;
      return parts.slice(-2).join('.');
    } catch {
      return null;
    }
  }
  
  function getHostname(urlString) {
    try {
      return new URL(urlString).hostname;
    } catch {
      return null;
    }
  }
  
  module.exports = { getRootDomain, getHostname };