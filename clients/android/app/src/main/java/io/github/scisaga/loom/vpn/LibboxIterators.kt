package io.github.scisaga.loom.vpn

import io.github.scisaga.libbox.NetworkInterface
import io.github.scisaga.libbox.NetworkInterfaceIterator
import io.github.scisaga.libbox.StringIterator

internal class Strings(values: List<String>) : StringIterator {
    private val iterator = values.iterator()
    private val size = values.size
    override fun hasNext(): Boolean = iterator.hasNext()
    override fun next(): String = iterator.next()
    override fun len(): Int = size
}

internal class Interfaces(values: List<NetworkInterface>) : NetworkInterfaceIterator {
    private val iterator = values.iterator()
    override fun hasNext(): Boolean = iterator.hasNext()
    override fun next(): NetworkInterface = iterator.next()
}
