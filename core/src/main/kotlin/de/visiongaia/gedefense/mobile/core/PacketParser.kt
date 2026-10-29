package de.visiongaia.gedefense.mobile.core

data class ParsedPacket(
    val version: Int,
    val protocol: Int,
    val source: IpAddress,
    val destination: IpAddress,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val length: Int,
)

object PacketParser {
    const val TCP=6; const val UDP=17
    fun parse(packet: ByteArray, length: Int=packet.size): ParsedPacket? {
        if(length<=0 || length>packet.size) return null
        return when((packet[0].toInt() ushr 4) and 0xF) { 4 -> parseV4(packet,length); 6 -> parseV6(packet,length); else -> null }
    }
    private fun parseV4(b:ByteArray,n:Int):ParsedPacket? {
        if(n<20) return null
        val ihl=(b[0].toInt() and 0x0F)*4; if(ihl<20 || ihl>n) return null
        val total=u16(b,2); if(total<ihl || total>n) return null
        val proto=b[9].toInt() and 255
        val src=IpAddress(4,v4=i32(b,12)); val dst=IpAddress(4,v4=i32(b,16))
        val fragmentOffset=u16(b,6) and 0x1FFF
        val ports=if(fragmentOffset==0) ports(b,ihl,total,proto) else null
        return ParsedPacket(4,proto,src,dst,ports?.first,ports?.second,total)
    }
    private fun parseV6(b:ByteArray,n:Int):ParsedPacket? {
        if(n<40) return null
        val payload=u16(b,4); val total=40+payload; if(total>n) return null
        var next=b[6].toInt() and 255; var off=40; var hops=0; var nonFirstFragment=false
        while(next in EXT_HEADERS) {
            if(++hops>8 || off+2>total) return null
            val old=next; next=b[off].toInt() and 255
            val size=when(old){ 44 -> { if(off+8>total)return null; val frag=u16(b,off+2); if((frag ushr 3)!=0)nonFirstFragment=true; 8 }; 51 -> ((b[off+1].toInt() and 255) + 2)*4; else -> ((b[off+1].toInt() and 255)+1)*8 }
            if(size<=0 || off+size>total) return null; off+=size
        }
        val src=IpAddress(6,v6Hi=i64(b,8),v6Lo=i64(b,16)); val dst=IpAddress(6,v6Hi=i64(b,24),v6Lo=i64(b,32))
        val ports=if(nonFirstFragment)null else ports(b,off,total,next)
        return ParsedPacket(6,next,src,dst,ports?.first,ports?.second,total)
    }
    private fun ports(b:ByteArray,off:Int,total:Int,proto:Int):Pair<Int,Int>? {
        if(proto!=TCP && proto!=UDP) return null
        if(off+4>total) return null
        return u16(b,off) to u16(b,off+2)
    }
    private fun u16(b:ByteArray,o:Int)=((b[o].toInt() and 255) shl 8) or (b[o+1].toInt() and 255)
    private fun i32(b:ByteArray,o:Int)=((b[o].toInt() and 255) shl 24) or ((b[o+1].toInt() and 255) shl 16) or ((b[o+2].toInt() and 255) shl 8) or (b[o+3].toInt() and 255)
    private fun i64(b:ByteArray,o:Int):Long { var v=0L; for(i in 0 until 8) v=(v shl 8) or (b[o+i].toLong() and 255L); return v }
    private val EXT_HEADERS=setOf(0,43,44,51,60,135,139,140)
}
