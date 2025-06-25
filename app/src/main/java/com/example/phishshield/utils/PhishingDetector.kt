package com.example.phishshield.utils

import com.example.phishshield.models.AuditItem
import com.example.phishshield.models.AuditReport
import com.example.phishshield.models.UrlAnalysisResult
import java.net.URL
import java.util.regex.Pattern

class PhishingDetector {

    private val suspiciousWords = listOf(
        "verify", "urgent", "suspended", "expired", "confirm", "update",
        "secure", "bank", "paypal", "amazon", "microsoft", "google",
        "login", "signin", "account", "password", "credit", "card"
    )

    private val phishingKeywords = listOf(
        "phishing", "scam", "fake", "fraud", "malware", "virus",
        "hack", "compromised", "spoof", "credential"
    )

    private val legitimateTLDs = listOf(
        "com", "org", "net", "edu", "gov", "mil",
        "co", "io", "ai", "biz", "info"
    )

    private val suspiciousSpecialChars = listOf(
        "%", "@", "#", "$", "^", "&", "*", "!", "~"
    )

    fun analyzeUrl(urlString: String): UrlAnalysisResult {
        val auditItems = mutableListOf<AuditItem>()
        var riskScore = 0.0f

        try {
            val url = URL(if (!urlString.startsWith("http")) "http://$urlString" else urlString)

            // Check HTTPS
            val httpsResult = checkHttps(url)
            auditItems.add(httpsResult.first)
            riskScore += httpsResult.second * 0.20f // Weighted at 20%

            // Check IP address usage
            val ipResult = checkIpAddress(url)
            auditItems.add(ipResult.first)
            riskScore += ipResult.second * 0.25f // Weighted at 25%

            // Check domain age
            val domainAgeResult = checkDomainAge(url)
            auditItems.add(domainAgeResult.first)
            riskScore += domainAgeResult.second * 0.15f // Weighted at 15%

            // Check suspicious words
            val suspiciousWordsResult = checkSuspiciousWords(url)
            auditItems.add(suspiciousWordsResult.first)
            riskScore += suspiciousWordsResult.second * 0.15f // Weighted at 15%

            // Check subdomain count
            val subdomainResult = checkSubdomains(url)
            auditItems.add(subdomainResult.first)
            riskScore += subdomainResult.second * 0.10f // Weighted at 10%

            // Check URL length
            val urlLengthResult = checkUrlLength(urlString)
            auditItems.add(urlLengthResult.first)
            riskScore += urlLengthResult.second * 0.05f // Weighted at 5%

            // Check for URL shorteners
            val shortenerResult = checkUrlShortener(url)
            auditItems.add(shortenerResult.first)
            riskScore += shortenerResult.second * 0.10f // Weighted at 10%

            // Check special characters
            val specialCharResult = checkSpecialCharacters(urlString)
            auditItems.add(specialCharResult.first)
            riskScore += specialCharResult.second * 0.05f // Weighted at 5%

            // Check TLD validity
            val tldResult = checkTLD(url)
            auditItems.add(tldResult.first)
            riskScore += tldResult.second * 0.10f // Weighted at 10%

            // Check domain reputation (simulated)
            val reputationResult = checkDomainReputation(url)
            auditItems.add(reputationResult.first)
            riskScore += reputationResult.second * 0.20f // Weighted at 20%

        } catch (e: Exception) {
            auditItems.add(
                AuditItem(
                    title = "URL Format",
                    description = "Invalid URL format detected",
                    value = "Invalid",
                    passed = false,
                    riskLevel = AuditItem.RiskLevel.HIGH,
                    category = AuditItem.AuditCategory.TECHNICAL
                )
            )
            riskScore += 0.3f
        }

        val passedChecks = auditItems.count { it.passed }
        val totalChecks = auditItems.size
        // Adjusted safety threshold for more accurate classification
        val isSafe = riskScore <= 0.35f && passedChecks >= (totalChecks * 0.7f).toInt()

        val auditReport = AuditReport(
            auditItems = auditItems,
            recommendations = AuditReport.generateRecommendations(auditItems),
            overallScore = 1.0f - riskScore,
            totalChecks = totalChecks,
            passedChecks = passedChecks
        )

        return UrlAnalysisResult(
            url = urlString,
            isSafe = isSafe,
            riskScore = riskScore.coerceIn(0.0f, 1.0f),
            auditReport = auditReport
        )
    }

    private fun checkHttps(url: URL): Pair<AuditItem, Float> {
        val isHttps = url.protocol.equals("https", ignoreCase = true)
        return Pair(
            AuditItem(
                title = "HTTPS Security",
                description = "Checks if the URL uses secure HTTPS protocol",
                value = if (isHttps) "Secure (HTTPS)" else "Not Secure (HTTP)",
                passed = isHttps,
                riskLevel = if (isHttps) AuditItem.RiskLevel.LOW else AuditItem.RiskLevel.HIGH,
                category = AuditItem.AuditCategory.SECURITY
            ),
            if (isHttps) 0.0f else 0.25f // Increased risk for non-HTTPS
        )
    }

    private fun checkIpAddress(url: URL): Pair<AuditItem, Float> {
        val host = url.host
        val isIpAddress = Pattern.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$", host) ||
                Pattern.matches("^[0-9a-fA-F:]+$", host) // Added IPv6 support

        return Pair(
            AuditItem(
                title = "Domain vs IP Address",
                description = "Legitimate sites typically use domain names, not IP addresses",
                value = if (isIpAddress) "IP Address ($host)" else "Domain Name ($host)",
                passed = !isIpAddress,
                riskLevel = if (isIpAddress) AuditItem.RiskLevel.HIGH else AuditItem.RiskLevel.LOW,
                category = AuditItem.AuditCategory.DOMAIN
            ),
            if (isIpAddress) 0.3f else 0.0f // Increased risk for IP addresses
        )
    }

    private fun checkDomainAge(url: URL): Pair<AuditItem, Float> {
        val host = url.host.lowercase()
        // Enhanced domain age simulation
        val isNewDomain = host.length < 15 ||
                host.contains("temp") ||
                host.contains("new") ||
                host.contains("site") ||
                host.matches(Regex(".*\\d{4}.*")) // Check for numbers indicating recent years

        return Pair(
            AuditItem(
                title = "Domain Age",
                description = "Newer domains or those with temporary patterns are more likely to be used for phishing",
                value = if (isNewDomain) "Recently Created" else "Established Domain",
                passed = !isNewDomain,
                riskLevel = if (isNewDomain) AuditItem.RiskLevel.MEDIUM else AuditItem.RiskLevel.LOW,
                category = AuditItem.AuditCategory.DOMAIN
            ),
            if (isNewDomain) 0.15f else 0.0f
        )
    }

    private fun checkSuspiciousWords(url: URL): Pair<AuditItem, Float> {
        val urlString = url.toString().lowercase()
        val foundSuspiciousWords = suspiciousWords.filter { urlString.contains(it) }
        val foundPhishingWords = phishingKeywords.filter { urlString.contains(it) }

        val hasSuspiciousWords = foundSuspiciousWords.isNotEmpty() || foundPhishingWords.isNotEmpty()
        val riskMultiplier = when {
            foundPhishingWords.isNotEmpty() -> 0.4f
            foundSuspiciousWords.isNotEmpty() -> 0.15f
            else -> 0.0f
        }

        return Pair(
            AuditItem(
                title = "Suspicious Keywords",
                description = "Checks for common phishing-related words in the URL",
                value = if (hasSuspiciousWords)
                    "Found: ${(foundSuspiciousWords + foundPhishingWords).joinToString(", ")}"
                else "No suspicious words detected",
                passed = !hasSuspiciousWords,
                riskLevel = when {
                    foundPhishingWords.isNotEmpty() -> AuditItem.RiskLevel.HIGH
                    foundSuspiciousWords.isNotEmpty() -> AuditItem.RiskLevel.MEDIUM
                    else -> AuditItem.RiskLevel.LOW
                },
                category = AuditItem.AuditCategory.CONTENT
            ),
            riskMultiplier * (foundSuspiciousWords.size + foundPhishingWords.size * 2)
        )
    }

    private fun checkSubdomains(url: URL): Pair<AuditItem, Float> {
        val host = url.host
        val subdomainCount = host.split(".").size - 2
        val hasExcessiveSubdomains = subdomainCount > 2

        return Pair(
            AuditItem(
                title = "Subdomain Analysis",
                description = "Multiple subdomains can indicate phishing attempts",
                value = "$subdomainCount subdomains detected",
                passed = !hasExcessiveSubdomains,
                riskLevel = when {
                    subdomainCount > 4 -> AuditItem.RiskLevel.HIGH
                    subdomainCount > 2 -> AuditItem.RiskLevel.MEDIUM
                    else -> AuditItem.RiskLevel.LOW
                },
                category = AuditItem.AuditCategory.DOMAIN
            ),
            if (hasExcessiveSubdomains) 0.1f * subdomainCount else 0.0f
        )
    }

    private fun checkUrlLength(urlString: String): Pair<AuditItem, Float> {
        val isLongUrl = urlString.length > 75 // Lowered threshold for more sensitivity

        return Pair(
            AuditItem(
                title = "URL Length",
                description = "Long URLs are often used to hide phishing attempts",
                value = "${urlString.length} characters",
                passed = !isLongUrl,
                riskLevel = when {
                    urlString.length > 150 -> AuditItem.RiskLevel.HIGH
                    urlString.length > 75 -> AuditItem.RiskLevel.MEDIUM
                    else -> AuditItem.RiskLevel.LOW
                },
                category = AuditItem.AuditCategory.TECHNICAL
            ),
            when {
                urlString.length > 150 -> 0.1f
                urlString.length > 75 -> 0.05f
                else -> 0.0f
            }
        )
    }

    private fun checkUrlShortener(url: URL): Pair<AuditItem, Float> {
        val host = url.host.lowercase()
        val shorteners = listOf(
            "bit.ly", "tinyurl.com", "short.link", "t.co",
            "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly"
        )
        val isShortener = shorteners.any { host.contains(it) }

        return Pair(
            AuditItem(
                title = "URL Shortener",
                description = "Shortened URLs can hide the actual destination",
                value = if (isShortener) "URL Shortener Detected ($host)" else "Direct URL",
                passed = !isShortener,
                riskLevel = if (isShortener) AuditItem.RiskLevel.HIGH else AuditItem.RiskLevel.LOW,
                category = AuditItem.AuditCategory.TECHNICAL
            ),
            if (isShortener) 0.2f else 0.0f // Increased risk for shorteners
        )
    }

    private fun checkSpecialCharacters(urlString: String): Pair<AuditItem, Float> {
        val foundSpecialChars = suspiciousSpecialChars.filter { urlString.contains(it) }
        val hasSuspiciousChars = foundSpecialChars.isNotEmpty()

        return Pair(
            AuditItem(
                title = "Special Characters",
                description = "Unusual special characters can indicate phishing attempts",
                value = if (hasSuspiciousChars)
                    "Found: ${foundSpecialChars.joinToString(", ")}"
                else "No suspicious special characters",
                passed = !hasSuspiciousChars,
                riskLevel = when {
                    foundSpecialChars.size > 2 -> AuditItem.RiskLevel.HIGH
                    foundSpecialChars.isNotEmpty() -> AuditItem.RiskLevel.MEDIUM
                    else -> AuditItem.RiskLevel.LOW
                },
                category = AuditItem.AuditCategory.TECHNICAL
            ),
            if (hasSuspiciousChars) 0.05f * foundSpecialChars.size else 0.0f
        )
    }

    private fun checkTLD(url: URL): Pair<AuditItem, Float> {
        val tld = url.host.substringAfterLast(".")
        val isLegitimateTLD = legitimateTLDs.contains(tld.lowercase())

        return Pair(
            AuditItem(
                title = "Top-Level Domain",
                description = "Checks if the URL uses a common, legitimate TLD",
                value = "TLD: $tld",
                passed = isLegitimateTLD,
                riskLevel = if (isLegitimateTLD) AuditItem.RiskLevel.LOW else AuditItem.RiskLevel.MEDIUM,
                category = AuditItem.AuditCategory.DOMAIN
            ),
            if (isLegitimateTLD) 0.0f else 0.15f
        )
    }

    private fun checkDomainReputation(url: URL): Pair<AuditItem, Float> {
        val host = url.host.lowercase()
        // Simulated reputation check (in real app, would use external API)
        val knownBadDomains = listOf("malicious", "phish", "scam", "fake")
        val isSuspicious = knownBadDomains.any { host.contains(it) }

        return Pair(
            AuditItem(
                title = "Domain Reputation",
                description = "Checks domain against known malicious patterns",
                value = if (isSuspicious) "Suspicious domain detected" else "No known issues",
                passed = !isSuspicious,
                riskLevel = if (isSuspicious) AuditItem.RiskLevel.HIGH else AuditItem.RiskLevel.LOW,
                category = AuditItem.AuditCategory.REPUTATION
            ),
            if (isSuspicious) 0.25f else 0.0f
        )
    }
}