package com.example.phishshield



import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.phishshield.adapters.AuditReportAdapter
import com.example.phishshield.models.AuditReport
import com.example.phishshield.models.UrlAnalysisResult
import com.example.phishshield.utils.PhishingDetector
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {

    private lateinit var urlInput: EditText
    private lateinit var checkButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var resultCard: CardView
    private lateinit var resultIcon: ImageView
    private lateinit var resultTitle: TextView
    private lateinit var resultDescription: TextView
    private lateinit var auditRecyclerView: RecyclerView
    private lateinit var recommendationsCard: CardView
    private lateinit var recommendationsText: TextView
    private lateinit var auditReportAdapter: AuditReportAdapter

    private val phishingDetector = PhishingDetector()
    private val mainScope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initializeViews()
        setupRecyclerView()
        setupClickListeners()
    }

    private fun initializeViews() {
        urlInput = findViewById(R.id.url_input)
        checkButton = findViewById(R.id.check_button)
        progressBar = findViewById(R.id.progress_bar)
        resultCard = findViewById(R.id.result_card)
        resultIcon = findViewById(R.id.result_icon)
        resultTitle = findViewById(R.id.result_title)
        resultDescription = findViewById(R.id.result_description)
        auditRecyclerView = findViewById(R.id.audit_recycler_view)
        recommendationsCard = findViewById(R.id.recommendations_card)
        recommendationsText = findViewById(R.id.recommendations_text)
    }

    private fun setupRecyclerView() {
        auditReportAdapter = AuditReportAdapter()
        auditRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = auditReportAdapter
        }
    }

    private fun setupClickListeners() {
        checkButton.setOnClickListener {
            val url = urlInput.text.toString().trim()
            if (url.isNotEmpty()) {
                analyzeUrl(url)
            } else {
                Toast.makeText(this, "Please enter a URL", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun analyzeUrl(url: String) {
        showLoading(true)
        hideResults()

        mainScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    phishingDetector.analyzeUrl(url)
                }
                displayResults(result)
            } catch (e: Exception) {
                showError("Error analyzing URL: ${e.message}")
            } finally {
                showLoading(false)
            }
        }
    }

    private fun displayResults(result: UrlAnalysisResult) {
        // Show result card
       // resultCard.visibility = View.VISIBLE

        // Set result icon and colors
        /*if (result.isSafe) {
            resultIcon.setImageResource(R.drawable.ic_shield_safe)
            resultTitle.text = "Safe URL"
            resultTitle.setTextColor(getColor(R.color.safe_green))
            resultDescription.text = "This URL appears to be legitimate and safe to visit."
            resultCard.setCardBackgroundColor(getColor(R.color.safe_background))
        } else {
            resultIcon.setImageResource(R.drawable.ic_warning)
            resultTitle.text = "Suspicious URL"
            resultTitle.setTextColor(getColor(R.color.danger_red))
            resultDescription.text = "This URL shows signs of being a phishing attempt. Exercise caution!"
            resultCard.setCardBackgroundColor(getColor(R.color.danger_background))
        }*/

        // Display audit report
        auditReportAdapter.updateAuditItems(result.auditReport.auditItems)

        // Show recommendations if URL is suspicious
        if (!result.isSafe) {
            showRecommendations(result.auditReport.recommendations)
        } else {
            hideRecommendations()
        }
    }

    private fun showRecommendations(recommendations: List<String>) {
        recommendationsCard.visibility = View.VISIBLE
        val recommendationsFormatted = recommendations.joinToString("\n\n") { "• $it" }
        recommendationsText.text = recommendationsFormatted
    }

    private fun hideRecommendations() {
        recommendationsCard.visibility = View.GONE
    }

    private fun showLoading(show: Boolean) {
        progressBar.visibility = if (show) View.VISIBLE else View.GONE
        checkButton.isEnabled = !show
    }

    private fun hideResults() {
        resultCard.visibility = View.GONE
        recommendationsCard.visibility = View.GONE
    }

    private fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        mainScope.cancel()
    }
}