package com.aerobox.service

import android.net.DnsResolver
import android.os.CancellationSignal
import android.system.ErrnoException
import android.system.OsConstants
import android.util.Log
import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

object LocalResolverTransport : LocalDNSTransport {
    private const val TAG = "LocalResolverTransport"

    @Suppress("DEPRECATION")
    private val dnsResolver by lazy {
        DnsResolver.getInstance()
    }

    override fun raw(): Boolean = true

    override fun exchange(ctx: ExchangeContext, message: ByteArray) {
        val defaultNetwork = DefaultNetworkMonitor.defaultNetwork
            ?: error("missing default network")
        resolve(ctx, ctx::rawSuccess) { signal, callback ->
            dnsResolver.rawQuery(
                defaultNetwork,
                message,
                DnsResolver.FLAG_NO_RETRY,
                Dispatchers.IO.asExecutor(),
                signal,
                callback
            )
        }
    }

    override fun lookup(ctx: ExchangeContext, network: String, domain: String) {
        val defaultNetwork = DefaultNetworkMonitor.defaultNetwork
            ?: error("missing default network")
        resolve<Collection<InetAddress>>(ctx, { answer ->
            ctx.success(answer.mapNotNull { it.hostAddress }.joinToString("\n"))
        }) { signal, callback ->
            val type = when {
                network.endsWith("4") -> DnsResolver.TYPE_A
                network.endsWith("6") -> DnsResolver.TYPE_AAAA
                else -> null
            }
            if (type != null) {
                dnsResolver.query(
                    defaultNetwork,
                    domain,
                    type,
                    DnsResolver.FLAG_NO_RETRY,
                    Dispatchers.IO.asExecutor(),
                    signal,
                    callback
                )
            } else {
                dnsResolver.query(
                    defaultNetwork,
                    domain,
                    DnsResolver.FLAG_NO_RETRY,
                    Dispatchers.IO.asExecutor(),
                    signal,
                    callback
                )
            }
        }
    }

    private fun <T : Any> resolve(
        ctx: ExchangeContext,
        onAnswer: (T) -> Unit,
        submit: (CancellationSignal, DnsResolver.Callback<T>) -> Unit
    ) = runBlocking {
        suspendCoroutine { continuation ->
            val signal = CancellationSignal()
            val completed = AtomicBoolean(false)

            fun complete(result: () -> Unit) {
                if (!completed.compareAndSet(false, true)) return
                try {
                    result()
                } catch (error: Exception) {
                    Log.w(TAG, "DNS result handling failed", error)
                    ctx.errnoCode(OsConstants.EIO)
                } finally {
                    continuation.resume(Unit)
                }
            }

            // Android may omit the callback after cancellation; release the native caller too.
            ctx.onCancel {
                complete {
                    signal.cancel()
                    ctx.errnoCode(OsConstants.ECANCELED)
                }
            }

            val callback = object : DnsResolver.Callback<T> {
                override fun onAnswer(answer: T, rcode: Int) {
                    complete {
                        if (rcode == 0) onAnswer(answer) else ctx.errorCode(rcode)
                    }
                }

                override fun onError(error: DnsResolver.DnsException) {
                    complete {
                        val cause = error.cause
                        if (cause is ErrnoException) {
                            ctx.errnoCode(cause.errno)
                        } else {
                            Log.w(TAG, "DNS query failed", error)
                            ctx.errnoCode(OsConstants.EIO)
                        }
                    }
                }
            }

            if (!completed.get()) {
                try {
                    submit(signal, callback)
                } catch (error: Exception) {
                    complete {
                        Log.w(TAG, "DNS query submission failed", error)
                        ctx.errnoCode(OsConstants.EIO)
                    }
                }
            }
        }
    }
}
