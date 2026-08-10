# Building Warden Supreme

* Build Tool: Gradle
* Android Build Tools required
* Apple Host required for Apple tests

## Building
* Clone recursively
* The test suite contains test data that sadly cannot be made public. Hence:
    * Either add a file `supreme/common/src/jvmTest/resources/DebugStatements.csv` with collected debug statements
    * Or: Set the environment vatriable `NO_PRIVATE_TEST_DATA` to `true`
* To publish locally: `publishAllpublicationsToMavenLocal`
* See Project structure in the official documentation for info on which module does what

If you change behaviour in a braking way or `AttestationChallenge` changes shape, bump the `CURRENT_VERSION`and check if
older versin can still be used in some scenarios for improved compat