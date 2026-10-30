import { UrlFeatures } from '../types/extension';
import { sha256 } from './crypto';

const KNOWN_BRANDS = [
  'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'facebook',
  'instagram', 'bankofamerica', 'chase', 'wellsfargo', 'binance', 'coinbase'
];

const KNOWN_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly'
];

export async function extractUrlFeatures(rawUrl: string): Promise<UrlFeatures> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch (e) {
    parsedUrl = new URL('http://unknown-domain.invalid');
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const pathAndQuery = parsedUrl.pathname + parsedUrl.search;

  // 1. IP Host Check
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hasIpHost = ipRegex.test(hostname);

  // 2. Punycode check
  const isPunycode = hostname.includes('xn--');

  // 3. Subdomains and Public Suffix
  const parts = hostname.split('.');
  const subdomainCount = parts.length > 2 ? parts.length - 2 : 0;
  const publicSuffix = parts.length > 1 ? parts[parts.length - 1] : 'unknown';

  // 4. Domain Root Computation
  const domainRoot = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const domainRootHash = await sha256(domainRoot);

  // 5. Special Character & Separator Analysis
  const specialChars = (rawUrl.match(/[@%&=_\-\?\#]/g) || []).length;
  const excessiveSeparators = (hostname.match(/[\-]/g) || []).length > 3;

  // 6. Brand In Subdomain Check
  const subdomainsStr = parts.slice(0, parts.length - 2).join('.');
  const brandInSubdomain = KNOWN_BRANDS.some(brand => subdomainsStr.includes(brand));

  // 7. Suspicious Port Check
  const standardPorts = ['', '80', '443'];
  const suspiciousPort = !standardPorts.includes(parsedUrl.port);

  // 8. Suspicious Encoding Check
  const suspiciousEncoding = /%[0-9a-f]{2}/i.test(parsedUrl.search) || rawUrl.includes('%2f');

  // 9. Shortener check
  const isShortened = KNOWN_SHORTENERS.some(shortener => hostname.endsWith(shortener));

  return {
    url_length: rawUrl.length,
    subdomain_count: subdomainCount,
    special_char_count: specialChars,
    has_ip_host: hasIpHost,
    is_punycode: isPunycode,
    suspicious_encoding: suspiciousEncoding,
    brand_in_subdomain: brandInSubdomain,
    excessive_separators: excessiveSeparators,
    suspicious_port: suspiciousPort,
    public_suffix: publicSuffix,
    is_shortened: isShortened,
    domain_root_hash: domainRootHash
  };
}
