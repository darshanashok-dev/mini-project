package com.cybersecurity.service;

import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.MatchedRule;
import com.cybersecurity.model.RulesConfig;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class UrlAnalyzer {

    private final ScoringEngine scoringEngine;
    private final RulesConfig rulesConfig;
    private final Map<String, RulesConfig.UrlRuleDef> ruleDefMap;

    // Local-only IPv4 regex pattern (strictly no DNS resolution)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)$"
    );

    // IPv6 pattern
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^\\[?[0-9a-fA-F:]+\\]?$"
    );

    // Suspicious file extensions in path
    private static final Pattern SUSPICIOUS_EXT_PATTERN = Pattern.compile(
            ".*\\.(apk|exe|scr|bat|cmd|msi|vbs|ps1|hta|iso)$",
            Pattern.CASE_INSENSITIVE
    );

    public UrlAnalyzer(ScoringEngine scoringEngine, RulesConfig rulesConfig) {
        this.scoringEngine = scoringEngine;
        this.rulesConfig = rulesConfig;
        this.ruleDefMap = new HashMap<>();

        if (rulesConfig != null && rulesConfig.getUrlRules() != null) {
            for (RulesConfig.UrlRuleDef r : rulesConfig.getUrlRules()) {
                this.ruleDefMap.put(r.getId(), r);
            }
        }
    }

    /**
     * Analyzes URL structure strictly through string inspection and java.net.URI parsing.
     * NEVER performs any network I/O, DNS resolution, or HTTP requests.
     */
    public AnalysisResult analyze(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return scoringEngine.buildResult(Collections.emptyList(), "url");
        }

        String trimmed = rawUrl.trim();
        List<MatchedRule> matchedRules = new ArrayList<>();

        // Normalization for URI parsing
        String parseableUrl = trimmed;
        if (!parseableUrl.contains("://")) {
            parseableUrl = "http://" + parseableUrl;
        }

        URI uri = null;
        String host = "";
        String path = "";
        String authority = "";

        try {
            uri = new URI(parseableUrl);
            host = (uri.getHost() != null) ? uri.getHost().toLowerCase(Locale.ROOT) : "";
            path = (uri.getPath() != null) ? uri.getPath() : "";
            authority = (uri.getRawAuthority() != null) ? uri.getRawAuthority() : "";
        } catch (Exception e) {
            // Fallback string extraction if URI syntax has quirks
            int schemeIdx = trimmed.indexOf("://");
            String noScheme = (schemeIdx != -1) ? trimmed.substring(schemeIdx + 3) : trimmed;
            int slashIdx = noScheme.indexOf('/');
            if (slashIdx != -1) {
                host = noScheme.substring(0, slashIdx).toLowerCase(Locale.ROOT);
                path = noScheme.substring(slashIdx);
            } else {
                host = noScheme.toLowerCase(Locale.ROOT);
                path = "";
            }
        }

        // Clean port if present in host
        if (host.contains(":")) {
            int colonIdx = host.indexOf(':');
            host = host.substring(0, colonIdx);
        }

        // 1. Check for numeric IP host
        if (isNumericIpHost(host)) {
            addMatchedRule(matchedRules, "URL_NUMERIC_IP", host,
                    "Host is a raw numeric IP address instead of a standard domain name: " + host);
        }

        // 2. Check for @ symbol in URL authority
        if (trimmed.contains("@") || authority.contains("@")) {
            String atSnippet = extractAtSnippet(trimmed);
            addMatchedRule(matchedRules, "URL_AT_SYMBOL", atSnippet,
                    "URL authority contains an '@' character, which can deceive users about the true destination host.");
        }

        // 3. Check for known URL shorteners
        if (isKnownShortener(host)) {
            addMatchedRule(matchedRules, "URL_SHORTENER", host,
                    "URL uses a known shortening service (" + host + ") which conceals the destination target.");
        }

        // 4. Check for excessive hyphens in hostname
        long hyphenCount = host.chars().filter(ch -> ch == '-').count();
        if (hyphenCount >= 3) {
            addMatchedRule(matchedRules, "URL_EXCESSIVE_HYPHENS", host,
                    "Hostname contains " + hyphenCount + " hyphens, a pattern common in phishing host masquerading.");
        }

        // 5. Check for deceptive brand subdomains
        String deceptiveEvidence = checkDeceptiveSubdomain(host);
        if (deceptiveEvidence != null) {
            addMatchedRule(matchedRules, "URL_DECEPTIVE_SUBDOMAIN", deceptiveEvidence,
                    "Subdomain includes a trusted brand name while belonging to an unrelated domain: " + deceptiveEvidence);
        }

        // 6. Check for look-alike domain (typosquatting / homoglyphs)
        String lookalikeEvidence = checkLookalikeDomain(host);
        if (lookalikeEvidence != null) {
            addMatchedRule(matchedRules, "URL_LOOKALIKE_DOMAIN", lookalikeEvidence,
                    "Domain name closely mimics a legitimate brand via character substitution or misspelling: " + lookalikeEvidence);
        }

        // 7. Check for unusually long, encoded, or executable path
        if (isSuspiciousPath(path, trimmed)) {
            String pathSnippet = path.length() > 60 ? path.substring(0, 60) + "..." : path;
            addMatchedRule(matchedRules, "URL_LONG_OR_ENCODED_PATH", pathSnippet,
                    "URL contains an unusually long path, multiple encoded characters, or direct references to executable/installer payloads.");
        }

        return scoringEngine.buildResult(matchedRules, "url");
    }

    private boolean isNumericIpHost(String host) {
        if (host == null || host.isBlank()) return false;
        return IPV4_PATTERN.matcher(host).matches() || (host.contains(":") && IPV6_PATTERN.matcher(host).matches());
    }

    private boolean isKnownShortener(String host) {
        if (host == null || rulesConfig == null || rulesConfig.getKnownShorteners() == null) {
            return false;
        }
        for (String shortener : rulesConfig.getKnownShorteners()) {
            if (host.equalsIgnoreCase(shortener) || host.endsWith("." + shortener.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private String checkDeceptiveSubdomain(String host) {
        if (host == null || rulesConfig == null || rulesConfig.getKnownBrands() == null) {
            return null;
        }

        String[] parts = host.split("\\.");
        if (parts.length < 3) {
            // Need at least subdomain, domain, tld (e.g. sub.example.com)
            return null;
        }

        // Extract registered base domain (e.g. last 2 labels like example.com)
        String baseDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];

        // Check if a known brand appears in the subdomain parts (not the base domain)
        for (RulesConfig.KnownBrand brand : rulesConfig.getKnownBrands()) {
            String brandName = brand.getName().toLowerCase(Locale.ROOT);
            String officialDomain = brand.getOfficialDomain().toLowerCase(Locale.ROOT);

            // If the base domain itself is the official domain, this is legitimate
            if (baseDomain.equalsIgnoreCase(officialDomain) || host.endsWith("." + officialDomain)) {
                continue;
            }

            // Check if any subdomain segment contains or equals the brand
            for (int i = 0; i < parts.length - 2; i++) {
                if (parts[i].equalsIgnoreCase(brandName) || parts[i].contains(brandName)) {
                    return parts[i] + "." + baseDomain;
                }
            }
        }
        return null;
    }

    private String checkLookalikeDomain(String host) {
        if (host == null || rulesConfig == null || rulesConfig.getKnownBrands() == null) {
            return null;
        }

        String[] parts = host.split("\\.");
        if (parts.length < 2) return null;

        // Inspect domain label (e.g. for paypa1.com or paypa1-security.com)
        String domainLabel = parts[parts.length - 2].toLowerCase(Locale.ROOT);
        String[] tokens = domainLabel.split("-");

        for (RulesConfig.KnownBrand brand : rulesConfig.getKnownBrands()) {
            String target = brand.getName().toLowerCase(Locale.ROOT);

            // Test both the entire label and individual hyphen-delimited tokens
            List<String> candidates = new ArrayList<>();
            candidates.add(domainLabel);
            for (String tok : tokens) {
                if (!tok.isBlank() && !tok.equals(domainLabel)) {
                    candidates.add(tok);
                }
            }

            for (String candidate : candidates) {
                if (candidate.equals(target)) {
                    continue;
                }

                // Normalized replacement for common leetspeak substitutions:
                // 0 -> o, 1 -> l, 3 -> e, 4 -> a, 5 -> s, rn -> m, vv -> w
                String normalized = candidate
                        .replace("0", "o")
                        .replace("1", "l")
                        .replace("3", "e")
                        .replace("4", "a")
                        .replace("5", "s")
                        .replace("rn", "m")
                        .replace("vv", "w");

                if (normalized.equals(target)) {
                    return candidate + " (mimicking " + target + ")";
                }

                // Check Levenshtein distance for close typosquatting (for brand names >= 4 chars)
                if (target.length() >= 4 && Math.abs(candidate.length() - target.length()) <= 1) {
                    int dist = computeLevenshteinDistance(candidate, target);
                    if (dist == 1) {
                        return candidate + " (close misspelling of " + target + ")";
                    }
                }
            }
        }
        return null;
    }

    private boolean isSuspiciousPath(String path, String fullUrl) {
        if (path == null) return false;

        // Path unusually long (> 50 chars)
        if (path.length() > 50) return true;

        // Multiple encoded segments (%20, %2f, etc.)
        long percentCount = path.chars().filter(ch -> ch == '%').count();
        if (percentCount >= 3) return true;

        // Suspicious executable or installer extension
        if (SUSPICIOUS_EXT_PATTERN.matcher(path).matches()) return true;

        return false;
    }

    private String extractAtSnippet(String url) {
        int idx = url.indexOf('@');
        if (idx == -1) return "@";
        int start = Math.max(0, idx - 15);
        int end = Math.min(url.length(), idx + 15);
        return url.substring(start, end);
    }

    private void addMatchedRule(List<MatchedRule> matchedRules, String ruleId, String matchedText, String defaultExplanation) {
        RulesConfig.UrlRuleDef def = ruleDefMap.get(ruleId);
        String name = (def != null && def.getName() != null) ? def.getName() : ruleId;
        int weight = (def != null) ? def.getWeight() : 10;
        String explanation = (def != null && def.getExplanation() != null) ? def.getExplanation() : defaultExplanation;

        matchedRules.add(new MatchedRule(ruleId, name, weight, matchedText, explanation));
    }

    private int computeLevenshteinDistance(String s1, String s2) {
        int[] prev = new int[s2.length() + 1];
        int[] curr = new int[s2.length() + 1];

        for (int j = 0; j <= s2.length(); j++) prev[j] = j;

        for (int i = 1; i <= s1.length(); i++) {
            curr[0] = i;
            for (int j = 1; j <= s2.length(); j++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            System.arraycopy(curr, 0, prev, 0, curr.length);
        }
        return prev[s2.length()];
    }
}
