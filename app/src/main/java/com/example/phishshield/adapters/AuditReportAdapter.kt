package com.example.phishshield.adapters



import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import com.example.phishshield.R
import com.example.phishshield.models.AuditItem

class AuditReportAdapter : RecyclerView.Adapter<AuditReportAdapter.AuditItemViewHolder>() {

    private var auditItems: List<AuditItem> = emptyList()

    fun updateAuditItems(newItems: List<AuditItem>) {
        val diffCallback = AuditItemDiffCallback(auditItems, newItems)
        val diffResult = DiffUtil.calculateDiff(diffCallback)

        auditItems = newItems
        diffResult.dispatchUpdatesTo(this)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AuditItemViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_audit_detail, parent, false)
        return AuditItemViewHolder(view)
    }

    override fun onBindViewHolder(holder: AuditItemViewHolder, position: Int) {
        holder.bind(auditItems[position])
    }

    override fun getItemCount(): Int = auditItems.size

    class AuditItemViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val statusIcon: ImageView = itemView.findViewById(R.id.status_icon)
        private val titleText: TextView = itemView.findViewById(R.id.audit_title)
        private val descriptionText: TextView = itemView.findViewById(R.id.audit_description)
        private val valueText: TextView = itemView.findViewById(R.id.audit_value)
        private val riskLevelText: TextView = itemView.findViewById(R.id.risk_level)

        fun bind(auditItem: AuditItem) {
            titleText.text = auditItem.title
            descriptionText.text = auditItem.description
            valueText.text = auditItem.value
            riskLevelText.text = auditItem.riskLevel.displayName

            // Set status icon
            if (auditItem.passed) {
                statusIcon.setImageResource(R.drawable.ic_check_circle)
                statusIcon.setColorFilter(Color.parseColor("#4CAF50"))
            } else {
                statusIcon.setImageResource(R.drawable.ic_error)
                statusIcon.setColorFilter(Color.parseColor("#F44336"))
            }

            // Set risk level color
            val riskColor = Color.parseColor(auditItem.riskLevel.color)
            riskLevelText.setTextColor(riskColor)

            // Set title color based on status
            if (auditItem.passed) {
                titleText.setTextColor(Color.parseColor("#2E7D32"))
            } else {
                titleText.setTextColor(Color.parseColor("#C62828"))
            }
        }
    }

    private class AuditItemDiffCallback(
        private val oldList: List<AuditItem>,
        private val newList: List<AuditItem>
    ) : DiffUtil.Callback() {

        override fun getOldListSize(): Int = oldList.size

        override fun getNewListSize(): Int = newList.size

        override fun areItemsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
            return oldList[oldItemPosition].title == newList[newItemPosition].title
        }

        override fun areContentsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
            return oldList[oldItemPosition] == newList[newItemPosition]
        }
    }
}