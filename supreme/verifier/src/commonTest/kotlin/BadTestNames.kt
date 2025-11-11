import de.infix.testBalloon.framework.core.testSuite


val BadNames by testSuite {
    val name = "#_/\\\n-##`´*+string" //play around with it
        testSuite("without display name") {
            test(name) {
            }
        }

        testSuite("with display name") {
            test(name, displayName = name) {
            }
        }


        testSuite("with suites name") {
            testSuite(name) {
                test("foo") {
                }
            }
        }


        testSuite("with suites display name") {
            testSuite(name, displayName = name) {
                test("foo") {

                }
            }
        }
}