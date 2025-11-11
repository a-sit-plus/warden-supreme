import de.infix.testBalloon.framework.core.testSuite


val BadNames by testSuite {

    //it is important to comment out all tests and suites on different levels and and enable selectively
    //this includes combinations of two test/suites
    //also examine the test reports that are generated

    val name = "#_/\\\n-##`´*+string" //play around with it

    //like this, it runs, and it produces a proper test report, but fails after the BadNames Suite, causing other suites to be skipped
    // but "UTP was aborted externally" and the exit code is non zero
    test(name) {

    }

    test("benign", displayName = name+name) {

    }

    //this works fine
    test(displayName = "benign", name = name+name+name) {

    }

    //the following fail in diffferent ways on Android, but run fine on the jvm

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