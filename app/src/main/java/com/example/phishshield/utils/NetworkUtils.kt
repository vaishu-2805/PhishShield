package com.example.phishshield.utils


import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class NetworkUtils {

    companion object {
        /**
         * Check if the device has an active internet connection
         */
        fun isNetworkAvailable(context: Context): Boolean {
            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = connectivityManager.activeNetwork ?: return false
            val networkCapabilities = connectivityManager.getNetworkCapabilities(network) ?: return false

            return when {
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> true
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> true
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> true
                else -> false
            }
        }

        /**
         * Check if a URL is reachable and get response details
         */
        suspend fun checkUrlReachability(urlString: String): UrlReachabilityResult {
            return withContext(Dispatchers.IO) {
                try {
                    val url = URL(urlString)
                    val connection = url.openConnection() as HttpURLConnection

                    connection.apply {
                        requestMethod = "HEAD"
                        connectTimeout = 5000
                        readTimeout = 5000
                        instanceFollowRedirects = false
                    }

                    val responseCode = connection.responseCode
                    val contentLength = connection.contentLength
                    val lastModified = connection.lastModified
                    val serverHeader = connection.getHeaderField("Server")
                    val locationHeader = connection.getHeaderField("Location")

                    connection.disconnect()

                    UrlReachabilityResult(
                        isReachable = responseCode in 200..399,
                        responseCode = responseCode,
                        contentLength = contentLength,
                        lastModified = lastModified,
                        serverInfo = serverHeader,
                        redirectLocation = locationHeader,
                        isRedirect = responseCode in 300..399
                    )
                } catch (e: IOException) {
                    UrlReachabilityResult(
                        isReachable = false,
                        responseCode = -1,
                        error = e.message
                    )
                } catch (e: Exception) {
                    UrlReachabilityResult(
                        isReachable = false,
                        responseCode = -1,
                        error = "Unexpected error: ${e.message}"
                    )
                }
            }
        }

        /**
         * Extract domain from URL
         */
        fun extractDomain(urlString: String): String? {
            return try {
                val url = URL(if (!urlString.startsWith("http")) "http://$urlString" else urlString)
                url.host
            } catch (e: Exception) {
                null
            }
        }

        /**
         * Validate URL format
         */
        fun isValidUrl(urlString: String): Boolean {
            return try {
                URL(if (!urlString.startsWith("http")) "http://$urlString" else urlString)
                true
            } catch (e: Exception) {
                false
            }
        }

        /**
         * Get top-level domain from URL
         */
        fun getTopLevelDomain(urlString: String): String? {
            return try {
                val domain = extractDomain(urlString)
                domain?.substringAfterLast(".")
            } catch (e: Exception) {
                null
            }
        }

        /**
         * Check if URL uses a suspicious TLD
         */
        fun hasSuspiciousTLD(urlString: String): Boolean {
            val suspiciousTLDs = listOf(
                "tk", "ml", "ga", "cf", "click", "download", "zip", "review"
            )
            val tld = getTopLevelDomain(urlString)?.lowercase()
            return tld != null && suspiciousTLDs.contains(tld)
        }
    }

    data class UrlReachabilityResult(
        val isReachable: Boolean,
        val responseCode: Int,
        val contentLength: Int = -1,
        val lastModified: Long = 0,
        val serverInfo: String? = null,
        val redirectLocation: String? = null,
        val isRedirect: Boolean = false,
        val error: String? = null
    ) {
        fun getStatusDescription(): String {
            return when (responseCode) {
                200 -> "OK - Page loaded successfully"
                301 -> "Moved Permanently"
                302 -> "Found - Temporary redirect"
                403 -> "Forbidden - Access denied"
                404 -> "Not Found - Page doesn't exist"
                500 -> "Internal Server Error"
                503 -> "Service Unavailable"
                -1 -> error ?: "Network error"
                else -> "HTTP $responseCode"
            }
        }

        fun isSuccessful(): Boolean = responseCode in 200..299
        fun isRedirection(): Boolean = responseCode in 300..399
        fun isClientError(): Boolean = responseCode in 400..499
        fun isServerError(): Boolean = responseCode in 500..599
    }
}