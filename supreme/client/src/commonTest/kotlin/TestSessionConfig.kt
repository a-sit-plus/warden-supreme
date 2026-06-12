import at.asitplus.signum.Signum
import at.asitplus.signum.supreme.installSupreme
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession() {
    init { Signum.installSupreme() }
}
