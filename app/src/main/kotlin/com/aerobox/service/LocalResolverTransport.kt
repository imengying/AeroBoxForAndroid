package com.aerobox.service

import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import android.system.ErrnoException
import android.util.Log
import androidx.annotation.RequiresApi
import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import java.net.InetAddress
import java.net.UnknownHostException

object LocalResolverTransport : LocalDNSTransport {
    private const val TAG = "LocalResolverTransport"
    private const val RCODE_NXDOMAIN = 3
    private const val UNKNOWN_ERRNO = 114514

    override fun raw(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q

    @RequiresApi(Build.VERSION_CODES.Q)
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            lookupWithDnsResolver(ctx, network, domain)
        } else {
            lookupWithInetAddress(ctx, network, domain)
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
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

    private fun lookupWithInetAddress(ctx: ExchangeContext, network: String, domain: String) {
        Dispatchers.IO.asExecutor().execute {
            try {
                val resolved = try {
                    DefaultNetworkMonitor.defaultNetwork?.getAllByName(domain)
                } catch (_: UnknownHostException) {
                    null
                } ?: InetAddress.getAllByName(domain)

                val filtered = when {
                    network.endsWith("4") -> resolved.filter { it.address.size == 4 }
                    network.endsWith("6") -> resolved.filter { it.address.size == 16 }
                    else -> resolved.toList()
                }

                if (filtered.isNotEmpty()) {
                    ctx.success(filtered.mapNotNull { it.hostAddress }.joinToString("\n"))
                } else {
                    ctx.errnoCode(UNKNOWN_ERRNO)
                }
            } catch (_: UnknownHostException) {
                ctx.errorCode(RCODE_NXDOMAIN)
            } catch (e: Exception) {
                Log.w(TAG, "InetAddress lookup failed", e)
                ctx.errnoCode(UNKNOWN_ERRNO)
            }
        }
    }
}
