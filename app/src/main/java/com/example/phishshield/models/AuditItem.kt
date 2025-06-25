package com.example.phishshield.models

data class AuditItem(
    val title: String,
    val description: String,
    val value: String,
    val passed: Boolean,
    val riskLevel: RiskLevel,
    val category: AuditCategory
) {
    enum class RiskLevel(val displayName: String, val color: String) {
        LOW("Low Risk", "#4CAF50"),
        MEDIUM("Medium Risk", "#FF9800"),
        HIGH("High Risk", "#F44336"),
        CRITICAL("Critical Risk", "#D32F2F")
    }

    enum class AuditCategory(val displayName: String, val icon: String) {
        SECURITY("Security", "ic_shield_safe"),
        DOMAIN("Domain Analysis", "ic_domain"),
        CONTENT("Content Analysis", "ic_content"),
        TECHNICAL("Technical Details", "ic_technical"),
        REPUTATION("Reputation Analysis", "ic_reputation")
    }

    fun getStatusIcon(): String {
        return if (passed) "ic_check_circle" else "ic_error"
    }

    fun getStatusColor(): String {
        return if (passed) "#4CAF50" else "#F44336"
    }
}