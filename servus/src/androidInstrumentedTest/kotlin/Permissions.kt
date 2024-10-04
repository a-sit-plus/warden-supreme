import android.Manifest
import androidx.test.rule.GrantPermissionRule
import org.junit.Rule

interface Permissions {
    interface WriteExternalPermission {

        @get:Rule
        val writeExternalPermission: GrantPermissionRule
            get() = GrantPermissionRule.grant(Manifest.permission.ACCESS_NETWORK_STATE, Manifest.permission.INTERNET)

    }
}