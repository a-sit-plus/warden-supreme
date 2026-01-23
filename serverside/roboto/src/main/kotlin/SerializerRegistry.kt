package at.asitplus.attestation

import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass
import kotlin.reflect.KClass

class SerializerRegistry<T : Any>(
    @PublishedApi
    internal val base: KClass<T>
) {

    /**
     * Thrown during serializer registration failures.
     *
     * @param message The detail message explaining the reason for the exception.
     * @param firstAccess Contains the stack trace of the call that finalized registered serializer and prevented future
     * registration like the illegal call that causes this exception being thrown.
     */
    class RegistrationException(message: String, val firstAccess: Array<StackTraceElement>) :
        Throwable(message)


    /**
     * A mutable set used to hold instances of [SerializersModule] that are utilized
     * for configuring serialization behavior.
     */
    val modules: Set<SerializersModule> by lazy {
        inited = RuntimeException().stackTrace
        _configurationSerializerModules
    }

    @PublishedApi
    internal val _configurationSerializerModules = mutableSetOf<SerializersModule>()

    @PublishedApi
    internal var inited: Array<StackTraceElement>? = null

    /**
     * Can be used to register subclasses of [T].
     * **Must be called before ever accessing [`modules`]**, calling afterwards throw an [RegistrationException]!
     *
     * Neither thread-safe not coroutine-safe.
     */
    @Throws(RegistrationException::class)
    inline fun <reified C : T> register(clazz: KClass<C>) {
        inited?.let {
            throw RegistrationException(
                "AttestationRevocationList Loader Serializers are already initialized",
                it
            )
        }
        _configurationSerializerModules.add(SerializersModule {
            polymorphic(base) {
                subclass(clazz)
            }
        })
    }

}