package com.aerobox.core.network

enum class IpFamily { IPV4, IPV6 }

sealed interface IpDetectionResult {
    data object NotTested : IpDetectionResult
    data object Checking : IpDetectionResult
    data object Disabled : IpDetectionResult
    data object Failed : IpDetectionResult
    data class Reachable(val address: String) : IpDetectionResult
}

data class NetworkDetection(
    val ipv4: IpDetectionResult = IpDetectionResult.NotTested,
    val ipv6: IpDetectionResult = IpDetectionResult.NotTested
)
