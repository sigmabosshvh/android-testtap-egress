package com.example.rootlesspacketpoc;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class PacketBuilder {

    private static final int ETH_P_IP = 0x0800;
    private static final int ETH_P_ARP = 0x0806;
    private static final int ETH_P_8021Q = 0x8100;
    private static final int IPPROTO_TCP = 6;
    private static final int IPPROTO_UDP = 17;

    private static final int DHCP_DISCOVER = 1;
    public static final int DHCP_OFFER = 2;
    private static final int DHCP_REQUEST = 3;
    public static final int DHCP_ACK = 5;
    public static final int DHCP_NAK = 6;

    private static final int DHCP_SERVER_PORT = 67;
    private static final int DHCP_CLIENT_PORT = 68;
    private static final int DHCP_MAGIC_COOKIE = 0x63825363;

    private static final byte[] BROADCAST_MAC = {
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
    };
    private static final byte[] ZERO_IP = {0, 0, 0, 0};
    private static final byte[] BROADCAST_IP = {(byte) 255, (byte) 255, (byte) 255, (byte) 255};

    public static final int TCP_SYN = 0x02;
    public static final int TCP_ACK = 0x10;

    private PacketBuilder() {
    }

    public static byte[] buildTcpSyn(byte[] clientMac, byte[] gatewayMac, byte[] clientIp,
                                     byte[] remoteIp, int srcPort, int dstPort, long sequence) {
        byte[] tcp = new byte[20];

        writeU16(tcp, 0, srcPort);
        writeU16(tcp, 2, dstPort);
        writeU32(tcp, 4, sequence);
        tcp[12] = (byte) (5 << 4); // 20-byte TCP header
        tcp[13] = (byte) TCP_SYN;
        writeU16(tcp, 14, 64240);
        writeU16(tcp, 16, tcpChecksumIpv4(clientIp, remoteIp, tcp));

        return buildIpv4Frame(clientMac, gatewayMac, clientIp, remoteIp, IPPROTO_TCP, tcp, 0x4242);
    }

    private static int tcpChecksumIpv4(byte[] srcIp, byte[] dstIp, byte[] tcp) {
        byte[] pseudo = new byte[12 + tcp.length];
        System.arraycopy(srcIp, 0, pseudo, 0, 4);
        System.arraycopy(dstIp, 0, pseudo, 4, 4);
        pseudo[9] = IPPROTO_TCP;
        writeU16(pseudo, 10, tcp.length);
        System.arraycopy(tcp, 0, pseudo, 12, tcp.length);
        return checksum(pseudo, 0, pseudo.length);
    }

    public static final class TcpReply {
        public long acknowledgment;
        public int flags;
    }

    public static TcpReply parseTcpReply(byte[] frame, byte[] expectedRemoteIp, byte[] expectedClientIp,
                                         int expectedRemotePort, int expectedClientPort) {
        int ip = getIpv4Offset(frame);
        if (ip < 0 || frame.length < ip + 20) return null;

        int ihl = (frame[ip] & 0x0f) * 4;
        if (ihl < 20 || frame.length < ip + ihl + 20) return null;
        if ((frame[ip + 9] & 0xff) != IPPROTO_TCP) return null;
        if (!matchesAt(frame, ip + 12, expectedRemoteIp)) return null;
        if (!matchesAt(frame, ip + 16, expectedClientIp)) return null;

        int tcp = ip + ihl;
        if (readU16(frame, tcp) != expectedRemotePort || readU16(frame, tcp + 2) != expectedClientPort) {
            return null;
        }

        TcpReply reply = new TcpReply();
        reply.acknowledgment = readUnsignedInt(frame, tcp + 8);
        reply.flags = frame[tcp + 13] & 0xff;
        return reply;
    }

    public static byte[] buildDhcpDiscover(byte[] clientMac, int xid) {
        return buildDhcpClientPacket(clientMac, xid, DHCP_DISCOVER, null, null);
    }

    public static byte[] buildDhcpRequest(byte[] clientMac, int xid, byte[] requestedIp, byte[] serverId) {
        return buildDhcpClientPacket(clientMac, xid, DHCP_REQUEST, requestedIp, serverId);
    }

    private static byte[] buildDhcpClientPacket(byte[] clientMac, int xid, int messageType,
                                                byte[] requestedIp, byte[] serverId) {
        ByteBuffer d = ByteBuffer.allocate(548);

        d.put((byte) 1);             // BOOTREQUEST
        d.put((byte) 1);             // Ethernet
        d.put((byte) 6);             // hardware address length
        d.put((byte) 0);             // hops
        d.putInt(xid);
        d.putShort((short) 0);        // secs
        d.putShort((short) 0x8000);   // broadcast flag
        d.putInt(0);                  // ciaddr
        d.putInt(0);                  // yiaddr
        d.putInt(0);                  // siaddr
        d.putInt(0);                  // giaddr

        d.put(clientMac);
        while (d.position() < 44) d.put((byte) 0);   // chaddr[16]
        while (d.position() < 108) d.put((byte) 0);  // sname[64]
        while (d.position() < 236) d.put((byte) 0);  // file[128]

        d.putInt(DHCP_MAGIC_COOKIE);
        putOption(d, 53, new byte[]{(byte) messageType});

        byte[] clientId = new byte[7];
        clientId[0] = 1; // Ethernet
        System.arraycopy(clientMac, 0, clientId, 1, 6);
        putOption(d, 61, clientId);

        if (messageType == DHCP_REQUEST) {
            putOption(d, 50, requestedIp);
            putOption(d, 54, serverId);
        }

        putOption(d, 12, "rootless-poc".getBytes(StandardCharsets.US_ASCII));
        putOption(d, 55, new byte[]{1, 3, 6, 15, 51, 54, 58, 59});
        d.put((byte) 255); // END

        while (d.position() < 300) d.put((byte) 0);
        byte[] dhcp = Arrays.copyOf(d.array(), d.position());

        return buildIpv4UdpFrame(clientMac, BROADCAST_MAC, ZERO_IP, BROADCAST_IP,
                DHCP_CLIENT_PORT, DHCP_SERVER_PORT, dhcp, xid & 0xffff);
    }

    private static void putOption(ByteBuffer buffer, int type, byte[] value) {
        buffer.put((byte) type);
        buffer.put((byte) value.length);
        buffer.put(value);
    }

    public static final class DhcpInfo {
        public int messageType;
        public byte[] yiaddr;
        public byte[] serverId;
        public byte[] router;
    }

    public static DhcpInfo parseDhcp(byte[] frame, int expectedXid, byte[] clientMac) {
        int length = frame.length;
        int ip = getIpv4Offset(frame);
        if (ip < 0 || length < ip + 20) return null;

        int ihl = (frame[ip] & 0x0f) * 4;
        if (ihl < 20 || length < ip + ihl + 8) return null;
        if ((frame[ip + 9] & 0xff) != IPPROTO_UDP) return null;

        int udp = ip + ihl;
        if (readU16(frame, udp) != DHCP_SERVER_PORT || readU16(frame, udp + 2) != DHCP_CLIENT_PORT) {
            return null;
        }

        int dhcp = udp + 8;
        if (length < dhcp + 240) return null;
        if ((frame[dhcp] & 0xff) != 2) return null; // BOOTREPLY
        if (readInt(frame, dhcp + 4) != expectedXid) return null;
        if (!matchesAt(frame, dhcp + 28, clientMac)) return null;
        if (readInt(frame, dhcp + 236) != DHCP_MAGIC_COOKIE) return null;

        DhcpInfo info = new DhcpInfo();
        info.yiaddr = Arrays.copyOfRange(frame, dhcp + 16, dhcp + 20);
        byte[] sourceIp = Arrays.copyOfRange(frame, ip + 12, ip + 16);

        int p = dhcp + 240;
        while (p < length) {
            int type = frame[p++] & 0xff;
            if (type == 0) continue;
            if (type == 255 || p >= length) break;

            int optionLength = frame[p++] & 0xff;
            if (p + optionLength > length) break;

            switch (type) {
                case 53:
                    if (optionLength >= 1) info.messageType = frame[p] & 0xff;
                    break;
                case 3:
                    if (optionLength >= 4) info.router = Arrays.copyOfRange(frame, p, p + 4);
                    break;
                case 54:
                    if (optionLength >= 4) info.serverId = Arrays.copyOfRange(frame, p, p + 4);
                    break;
            }

            p += optionLength;
        }

        if (info.serverId == null) info.serverId = sourceIp;
        return info;
    }

    public static byte[] buildArpRequest(byte[] clientMac, byte[] clientIp, byte[] targetIp) {
        byte[] frame = new byte[60];

        System.arraycopy(BROADCAST_MAC, 0, frame, 0, 6);
        System.arraycopy(clientMac, 0, frame, 6, 6);
        writeU16(frame, 12, ETH_P_ARP);

        int arp = 14;
        writeU16(frame, arp, 1);             // Ethernet
        writeU16(frame, arp + 2, ETH_P_IP);  // IPv4
        frame[arp + 4] = 6;
        frame[arp + 5] = 4;
        writeU16(frame, arp + 6, 1);         // REQUEST
        System.arraycopy(clientMac, 0, frame, arp + 8, 6);
        System.arraycopy(clientIp, 0, frame, arp + 14, 4);
        // target MAC remains zero
        System.arraycopy(targetIp, 0, frame, arp + 24, 4);

        return frame;
    }

    public static byte[] parseArpReplyMac(byte[] frame, byte[] expectedSenderIp, byte[] clientMac) {
        int arp = getArpOffset(frame);
        if (arp < 0 || frame.length < arp + 28) return null;
        if (readU16(frame, arp + 6) != 2) return null; // REPLY
        if (!matchesAt(frame, arp + 14, expectedSenderIp)) return null;
        if (!matchesAt(frame, arp + 18, clientMac)) return null;
        return Arrays.copyOfRange(frame, arp + 8, arp + 14);
    }

    private static byte[] buildIpv4UdpFrame(byte[] srcMac, byte[] dstMac, byte[] srcIp, byte[] dstIp,
                                            int srcPort, int dstPort, byte[] payload, int id) {
        byte[] udp = new byte[8 + payload.length];
        writeU16(udp, 0, srcPort);
        writeU16(udp, 2, dstPort);
        writeU16(udp, 4, udp.length);
        System.arraycopy(payload, 0, udp, 8, payload.length);

        return buildIpv4Frame(srcMac, dstMac, srcIp, dstIp, IPPROTO_UDP, udp, id);
    }

    private static byte[] buildIpv4Frame(byte[] srcMac, byte[] dstMac, byte[] srcIp, byte[] dstIp,
                                         int protocol, byte[] payload, int id) {
        int ipLength = 20 + payload.length;
        byte[] frame = new byte[Math.max(14 + ipLength, 60)]; // Ethernet minimum without FCS

        System.arraycopy(dstMac, 0, frame, 0, 6);
        System.arraycopy(srcMac, 0, frame, 6, 6);
        writeU16(frame, 12, ETH_P_IP);

        int ip = 14;
        frame[ip] = 0x45;
        writeU16(frame, ip + 2, ipLength);
        writeU16(frame, ip + 4, id);
        frame[ip + 8] = 64;
        frame[ip + 9] = (byte) protocol;
        System.arraycopy(srcIp, 0, frame, ip + 12, 4);
        System.arraycopy(dstIp, 0, frame, ip + 16, 4);
        writeU16(frame, ip + 10, checksum(frame, ip, 20));
        System.arraycopy(payload, 0, frame, ip + 20, payload.length);

        return frame;
    }

    private static int getIpv4Offset(byte[] frame) {
        if (frame.length < 14) return -1;
        int type = readU16(frame, 12);
        if (type == ETH_P_IP) return 14;
        if (type == ETH_P_8021Q && frame.length >= 18 && readU16(frame, 16) == ETH_P_IP) return 18;
        return -1;
    }

    private static int getArpOffset(byte[] frame) {
        if (frame.length < 14) return -1;
        int type = readU16(frame, 12);
        if (type == ETH_P_ARP) return 14;
        if (type == ETH_P_8021Q && frame.length >= 18 && readU16(frame, 16) == ETH_P_ARP) return 18;
        return -1;
    }

    private static boolean matchesAt(byte[] packet, int offset, byte[] expected) {
        if (offset < 0 || offset + expected.length > packet.length) return false;
        for (int i = 0; i < expected.length; i++) {
            if (packet[offset + i] != expected[i]) return false;
        }
        return true;
    }

    private static int checksum(byte[] data, int offset, int length) {
        long sum = 0;
        int end = offset + length;
        int i = offset;

        while (i + 1 < end) {
            sum += ((data[i] & 0xff) << 8) | (data[i + 1] & 0xff);
            i += 2;
        }
        if (i < end) sum += (data[i] & 0xff) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);

        return (int) (~sum & 0xffff);
    }

    private static int readU16(byte[] b, int p) {
        return ((b[p] & 0xff) << 8) | (b[p + 1] & 0xff);
    }

    private static int readInt(byte[] b, int p) {
        return ((b[p] & 0xff) << 24)
                | ((b[p + 1] & 0xff) << 16)
                | ((b[p + 2] & 0xff) << 8)
                | (b[p + 3] & 0xff);
    }

    private static long readUnsignedInt(byte[] b, int p) {
        return readInt(b, p) & 0xffffffffL;
    }

    private static void writeU16(byte[] b, int p, int value) {
        b[p] = (byte) ((value >>> 8) & 0xff);
        b[p + 1] = (byte) (value & 0xff);
    }

    private static void writeU32(byte[] b, int p, long value) {
        b[p] = (byte) ((value >>> 24) & 0xff);
        b[p + 1] = (byte) ((value >>> 16) & 0xff);
        b[p + 2] = (byte) ((value >>> 8) & 0xff);
        b[p + 3] = (byte) (value & 0xff);
    }

    public static String ipv4(byte[] ip) {
        if (ip == null || ip.length < 4) return "(none)";
        return (ip[0] & 0xff) + "." + (ip[1] & 0xff) + "." + (ip[2] & 0xff) + "." + (ip[3] & 0xff);
    }

    public static String mac(byte[] mac) {
        if (mac == null || mac.length < 6) return "(none)";
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,
                mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);
    }
}
