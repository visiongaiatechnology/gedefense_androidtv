package de.visiongaia.gedefense.mobile.core

/**
 * Produces the smallest exact CIDR cover that can be expressed without widening the blocked set.
 *
 * Only sibling prefixes are merged, and every resulting parent is re-checked against the public
 * address policy. The algorithm never invents coverage for an address that was not already covered
 * by the input set.
 */
object RouteCompactor {
    fun compact(prefixes: Collection<IpPrefix>): List<IpPrefix> {
        if (prefixes.isEmpty()) return emptyList()
        val v4 = compactFamily(prefixes.asSequence().filter { it.family == 4 }.toList(), 32)
        val v6 = compactFamily(prefixes.asSequence().filter { it.family == 6 }.toList(), 128)
        return (v4 + v6).sortedWith(PREFIX_ORDER)
    }

    private fun compactFamily(input: List<IpPrefix>, maxBits: Int): List<IpPrefix> {
        val set = HashSet<IpPrefix>(input.size * 2)

        // Broad prefixes first. Any exact child already covered by a broader input is redundant.
        val ordered = input.asSequence()
            .filter { it.prefixLength in 1..maxBits && IpPrefix.isPublic(it) }
            .distinct()
            .sortedWith(PREFIX_ORDER)
            .toList()

        for (prefix in ordered) {
            if (!hasAncestor(prefix, set)) set += prefix
        }

        // Merge complete sibling pairs bottom-up. Newly created parents are considered by the next
        // iteration, allowing /32+/32 -> /31 -> /30 ... without repeatedly scanning the whole set.
        for (length in maxBits downTo 1) {
            val parents = HashMap<IpPrefix, MutableList<IpPrefix>>()
            for (child in set) {
                if (child.prefixLength != length) continue
                val parent = parentOf(child) ?: continue
                parents.getOrPut(parent) { ArrayList(2) }.add(child)
            }
            for ((parent, children) in parents) {
                if (children.size != 2 || !IpPrefix.isPublic(parent)) continue
                if (set.remove(children[0]) && set.remove(children[1])) {
                    if (!hasAncestor(parent, set)) set += parent
                }
            }
        }

        return set.sortedWith(PREFIX_ORDER)
    }

    private fun hasAncestor(prefix: IpPrefix, set: Set<IpPrefix>): Boolean {
        if (prefix.prefixLength <= 1) return false
        for (length in 1 until prefix.prefixLength) {
            val ancestor = if (prefix.family == 4) {
                IpPrefix(4, v4 = IpPrefix.maskV4(prefix.v4, length), prefixLength = length)
            } else {
                val masked = IpPrefix.maskV6(prefix.v6Hi, prefix.v6Lo, length)
                IpPrefix(6, v6Hi = masked.first, v6Lo = masked.second, prefixLength = length)
            }
            if (ancestor in set) return true
        }
        return false
    }

    private fun parentOf(prefix: IpPrefix): IpPrefix? {
        val length = prefix.prefixLength - 1
        if (length <= 0) return null
        return if (prefix.family == 4) {
            IpPrefix(4, v4 = IpPrefix.maskV4(prefix.v4, length), prefixLength = length)
        } else {
            val masked = IpPrefix.maskV6(prefix.v6Hi, prefix.v6Lo, length)
            IpPrefix(6, v6Hi = masked.first, v6Lo = masked.second, prefixLength = length)
        }
    }

    private val PREFIX_ORDER = Comparator<IpPrefix> { a, b ->
        var c = a.family.compareTo(b.family)
        if (c != 0) return@Comparator c
        c = a.prefixLength.compareTo(b.prefixLength)
        if (c != 0) return@Comparator c
        if (a.family == 4) {
            Integer.compareUnsigned(a.v4, b.v4)
        } else {
            c = java.lang.Long.compareUnsigned(a.v6Hi, b.v6Hi)
            if (c != 0) c else java.lang.Long.compareUnsigned(a.v6Lo, b.v6Lo)
        }
    }
}
