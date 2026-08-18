package at.asitplus.warden.collector

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class BackendHostTest {
    @Test
    fun acceptsOriginsWithoutAPath() {
        assertEquals("http://10.0.2.2:8080", backendHost("http://10.0.2.2:8080"))
        assertEquals("https://example.com", backendHost("example.com/"))
        assertNull(backendHost("https://example.com/some/path"))
    }
}
