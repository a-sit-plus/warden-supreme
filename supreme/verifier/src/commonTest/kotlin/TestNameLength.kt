import de.infix.testBalloon.framework.core.testSuite

operator fun String.times(times: Int): String {
    val str = StringBuilder()
    repeat(times) { str.append(this) }
    return str.toString()
}

var string = "#_/\\\n-##`´*+string"
var times = 10



val TestNameLength by testSuite {
        testSuite("without display name") {
            var name = string
            repeat(times) {
                name = name.times(it + 1)
                test(name) {

                }
            }
        }

        testSuite("with display name") {
            var name = string
            repeat(times) {
                name = name.times(it + 1)
                test(name = "$it", displayName = name) {

                }
            }
        }


        testSuite("with suites name") {
            var name = string
            repeat(times) {
                name = name.times(it + 1)
                testSuite(name) {
                    test("foo") {

                    }
                }
            }
        }


        testSuite("with suites display name") {
            var name = string
            repeat(times) {
                name = name.times(it + 1)
                testSuite(name = "/$it", displayName = name) {
                    test("foo") {

                    }
                }
            }
        }

}