package com.aerobox.service

import android.net.DnsResolver
import android.os.CancellationSignal
import android.system.ErrnoException
import android.util.Log
import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

object LocalResolverTransport : LocalDNSTransport {
    private const val TAG = "LocalResolverTransport"
    private const val UNKNOWN_ERRNO = 114514

    @Suppress("DEPRECATION")
    private val dnsResolver by lazy {
        DnsResolver.getInstance()
    }

    override fun raw(): Boolean = true

    override fun exchange(ctx: ExchangeContext, message: ByteArray) = runBlocking {
        val defaultNetwork = DefaultNetworkMonitor.defaultNetwork
            ?: error("missing default network")
        suspendCoroutine { continuation ->
            val signal = CancellationSignal()
            ctx.onCancel(signal::cancel)

            val callback = object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(answer: ByteArray, rcode: Int) {
                    try {
                        if (rcode == 0) {
                            ctx.rawSuccess(answer)
                        } else {
                            ctx.errorCode(rcode)
                        }
                    } catch (error: Exception) {
                        Log.w(TAG, "rawQuery result handling failed", error)
                        ctx.errnoCode(UNKNOWN_ERRNO)
                    } finally {
                        continuation.resume(Unit)
                    }
                }

                override fun onError(error: DnsResolver.DnsException) {
                    try {
                        reportDnsError(ctx, "rawQuery failed", error)
                    } finally {
                        continuation.resume(Unit)
                    }
                }
            }

            try {
                dnsResolver.rawQuery(
                    defaultNetwork,
                    message,
                    DnsResolver.FLAG_NO_RETRY,
                    Dispatchers.IO.asExecutor(),
                    signal,
                    callback
                )
            } catch (error: Exception) {
                Log.w(TAG, "rawQuery submission failed", error)
                ctx.errnoCode(UNKNOWN_ERRNO)
                continuation.resume(Unit)
            }
        }
    }

    override fun lookup(ctx: ExchangeContext, network: String, domain: String) {
        lookupWithDnsResolver(ctx, network, domain)
    }

    private fun lookupWithDnsResolver(ctx: ExchangeContext, network: String, domain: String) = runBlocking {
        val defaultNetwork = DefaultNetworkMonitor.defaultNetwork
            ?: error("missing default network")
        suspendCoroutine { continuation ->
            val signal = CancellationSignal()
            ctx.onCancel(signal::cancel)

            val callback = object : DnsResolver.Callback<Collection<InetAddress>> {
                override fun onAnswer(answer: Collection<InetAddress>, rcode: Int) {
                    try {
                        if (rcode == 0) {
                            ctx.success(answer.mapNotNull { it.hostAddress }.joinToString("\n"))
                        } else {
                            ctx.errorCode(rcode)
                        }
                    } catch (error: Exception) {
                        Log.w(TAG, "query result handling failed", error)
                        ctx.errnoCode(UNKNOWN_ERRNO)
                    } finally {
                        continuation.resume(Unit)
                    }
                }

                override fun onError(error: DnsResolver.DnsException) {
                    try {
                        reportDnsError(ctx, "query failed", error)
                    } finally {
                        continuation.resume(Unit)
                    }
                }
            }

            val type = when {
                network.endsWith("4") -> DnsResolver.TYPE_A
                network.endsWith("6") -> DnsResolver.TYPE_AAAA
                else -> null
            }

            try {
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
            } catch (error: Exception) {
                Log.w(TAG, "query submission failed", error)
                ctx.errnoCode(UNKNOWN_ERRNO)
                continuation.resume(Unit)
            }
        }
    }

    private fun reportDnsError(
        ctx: ExchangeContext,
        message: String,
        error: DnsResolver.DnsException
    ) {
        val cause = error.cause
        if (cause is ErrnoException) {
            ctx.errnoCode(cause.errno)
        } else {
            Log.w(TAG, message, error)
            ctx.errnoCode(UNKNOWN_ERRNO)
        }
    }
}
