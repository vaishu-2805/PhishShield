package com.example.phishshield.models

data class UrlAnalysisResult(
    val url: String,
    val isSafe: Boolean,
    val riskScore: Float, // 0.0 (safe) to 1.0 (very risky)
    val auditReport: AuditReport,
    val analysisTimestamp: Long = System.currentTimeMillis()
) {
    fun getRiskLevel(): String {
        return when {
            riskScore <= 0.3f -> "Low Risk"
            riskScore <= 0.6f -> "Medium Risk"
            riskScore <= 0.8f -> "High Risk"
            else -> "Very High Risk"
        }
    }

    fun getRiskDescription(): String {
        return when {
            riskScore <= 0.3f -> "This URL appears legitimate with minimal risk indicators."
            riskScore <= 0.6f -> "This URL has some suspicious characteristics but may be legitimate."
            riskScore <= 0.8f -> "This URL shows several phishing indicators and should be approached with caution."
            else -> "This URL exhibits strong phishing characteristics and is likely malicious."
        }
    }
}