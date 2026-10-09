package io.github.scisaga.loom.enrollment

import org.json.JSONArray
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections

/** Ephemeral platform input; unknown must never be treated as an empty underlay. */
internal fun readLocalInterfaceAddresses(): ByteArray = runCatching {
    val addresses = Collections.list(NetworkInterface.getNetworkInterfaces())
        .filter { it.isUp && !it.isLoopback }
        .flatMap { it.interfaceAddresses }
        .filter { it.address is Inet4Address }
        .map { "${checkNotNull(it.address.hostAddress)}/${it.networkPrefixLength}" }
        .distinct().sorted()
    JSONArray(addresses).toString()
}.getOrDefault("null").encodeToByteArray()
