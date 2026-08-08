package recloudstream

import android.content.Context
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.lagradost.cloudstream3.plugins.CloudstreamPlugin
import com.lagradost.cloudstream3.plugins.Plugin

@CloudstreamPlugin
class Anime47Plugin : Plugin() {

    private fun verifySignature(context: Context, expectedHashes: Set<String>): Boolean {
        return try {
            val packageManager = context.packageManager
            val signatures = if (android.os.Build.VERSION.SDK_INT >= 28) {
                val packageInfo = packageManager.getPackageInfo(
                    context.packageName,
                    android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
                )
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = packageManager.getPackageInfo(
                    context.packageName,
                    android.content.pm.PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            signatures?.forEach { signature ->
                val md = java.security.MessageDigest.getInstance("SHA-256")
                val digest = md.digest(signature.toByteArray())
                val hash = digest.joinToString(":") { "%02X".format(it) }
                if (expectedHashes.contains(hash)) {
                    return true
                }
            }
            false
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    override fun load(context: Context) {
        // Trực tiếp khởi tạo và đăng ký API
        val provider = Anime47Provider()
        registerMainAPI(provider)

        // Cài đặt setting
        this.openSettings = { ctx ->
            val activity = ctx as? AppCompatActivity
            if (activity != null) {
                Anime47SettingsDialog().show(activity.supportFragmentManager, "Anime47Settings")
            } else {
                Toast.makeText(ctx, "Lỗi: Không thể khởi tạo giao diện cài đặt", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
