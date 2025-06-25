package com.example.phishshield.models

    data class AuditReport(
        val auditItems: List<AuditItem>,
        val recommendations: List<String>,
        val overallScore: Float,
        val totalChecks: Int,
        val passedChecks: Int
    ) {
        fun getScorePercentage(): Int {
            return ((passedChecks.toFloat() / totalChecks.toFloat()) * 100).toInt()
        }

        fun getScoreColor(): String {
            return when {
                getScorePercentage() >= 80 -> "#4CAF50" // Green
                getScorePercentage() >= 60 -> "#FF9800" // Orange
                else -> "#F44336" // Red
            }
        }

        companion object {
            fun generateRecommendations(auditItems: List<AuditItem>): List<String> {
                val recommendations = mutableListOf<String>()

                auditItems.forEach { item ->
                    when {
                        !item.passed && item.title.contains("HTTPS", ignoreCase = true) -> {
                            recommendations.add("Always look for HTTPS (secure) connections when entering sensitive information.")
                        }
                        !item.passed && item.title.contains("Domain", ignoreCase = true) -> {
                            recommendations.add("Verify the domain name carefully - phishers often use similar-looking domains.")
                        }
                        !item.passed && item.title.contains("IP Address", ignoreCase = true) -> {
                            recommendations.add("Be cautious of URLs using IP addresses instead of domain names.")
                        }
                        !item.passed && item.title.contains("Suspicious", ignoreCase = true) -> {
                            recommendations.add("Watch out for suspicious words like 'verify', 'urgent', 'suspended' in URLs.")
                        }
                        !item.passed && item.title.contains("Subdomain", ignoreCase = true) -> {
                            recommendations.add("Multiple subdomains can be a sign of phishing - verify the main domain.")
                        }
                    }
                }

                if (recommendations.isEmpty()) {
                    recommendations.add("Always verify URLs before clicking, especially from unknown sources.")
                    recommendations.add("Check the sender's email address and look for spelling errors.")
                    recommendations.add("When in doubt, navigate to the website directly instead of clicking links.")
                }

                return recommendations
            }
        }
    }

