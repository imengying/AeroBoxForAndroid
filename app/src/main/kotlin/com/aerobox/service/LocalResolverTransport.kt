package com.aerobox.service

import android.net.DnsResolver
import android.os.CancellationSignal
import android.system.ErrnoException
import android.util.Log
import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import java.net.InetAddress

object LocalResolverTransport : LocalDNSTransport {
    private const val TAG = "LocalResolverTransport"
    private const val UNKNOWN_ERRNO = 114514

    override fun raw(): Boolean = true

    override fun exchange(ctx: ExchangeContext, message: ByteArray) {
        val signal = CancellationSignal()
        ctx.onCancel(signal::cancel)

        val callback = object : DnsResolver.Callback<ByteArray> {
            override fun onAnswer(answer: ByteArray, rcode: Int) {
                ctx.rawSuccess(answer)
            }

            override fun onError(error: DnsResolver.DnsException) {
                val cause = error.cause
                if (cause is ErrnoException) {
                    ctx.errnoCode(cause.errno)
                } else {
                    Log.w(TAG, "rawQuery failed", error)
                    ctx.errnoCode(UNKNOWN_ERRNO)
                }
            }
        }

        DnsResolver.getInstance().rawQuery(
            DefaultNetworkMonitor.defaultNetwork,
            message,
            DnsResolver.FLAG_NO_RETRY,
            Dispatchers.IO.asExecutor(),
            signal,
            callback
        )
    }

    override fun lookup(ctx: ExchangeContext, network: String, domain: String) {
        lookupWithDnsResolver(ctx, network, domain)
    }

    private fun lookupWithDnsResolver(ctx: ExchangeContext, network: String, domain: String) {
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
                } catch (e: Exception) {
                    Log.w(TAG, "query success handling failed", e)
                    ctx.errnoCode(UNKNOWN_ERRNO)
                }
            }

            override fun onError(error: DnsResolver.DnsException) {
                try {
                    val cause = error.cause
                    if (cause is ErrnoException) {
                        ctx.errnoCode(cause.errno)
                    } else {
                        Log.w(TAG, "query failed", error)
                        ctx.errnoCode(UNKNOWN_ERRNO)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "query error handling failed", e)
                    ctx.errnoCode(UNKNOWN_ERRNO)
                }
            }
        }

        val type = when {
            network.endsWith("4") -> DnsResolver.TYPE_A
            network.endsWith("6") -> DnsResolver.TYPE_AAAA
            else -> null
        }

        if (type != null) {
            DnsResolver.getInstance().query(
                DefaultNetworkMonitor.defaultNetwork,
                domain,
                type,
                DnsResolver.FLAG_NO_RETRY,
                Dispatchers.IO.asExecutor(),
                signal,
                callback
            )
        } else {
            DnsResolver.getInstance().query(
                DefaultNetworkMonitor.defaultNetwork,
                domain,
                DnsResolver.FLAG_NO_RETRY,
                Dispatchers.IO.asExecutor(),
                signal,
                callback
            )
        }
    }
}
