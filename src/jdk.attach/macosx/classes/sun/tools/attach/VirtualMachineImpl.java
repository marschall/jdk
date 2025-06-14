/*
 * Copyright (c) 2005, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package sun.tools.attach;

import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.spi.AttachProvider;

import jdk.internal.misc.VM;
import sun.nio.fs.UnixUserPrincipals;

import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Set;

import static java.lang.foreign.MemorySegment.NULL;

import static sun.tools.attach.MacOs.CTL_KERN;
import static sun.tools.attach.MacOs.C_CHAR;
import static sun.tools.attach.MacOs.C_INT;
import static sun.tools.attach.MacOs.KERN_PROC;
import static sun.tools.attach.MacOs.KERN_PROC_PID;
import static sun.tools.attach.MacOs.PATH_MAX;
import static sun.tools.attach.MacOs.SIGQUIT;
import static sun.tools.attach.MacOs._CS_DARWIN_USER_TEMP_DIR;
import static sun.tools.attach.MacOs.confstr;
import static sun.tools.attach.MacOs.kill;
import static sun.tools.attach.MacOs.sigismember;
import static sun.tools.attach.MacOs.size_t;

import java.io.IOException;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;


import java.nio.file.attribute.UserPrincipal;

import static java.nio.file.attribute.PosixFilePermission.GROUP_READ;
import static java.nio.file.attribute.PosixFilePermission.GROUP_WRITE;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_READ;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE;

/*
 * Bsd implementation of HotSpotVirtualMachine
 */
@SuppressWarnings("restricted")
public class VirtualMachineImpl extends HotSpotVirtualMachine {
    private static final Set<PosixFilePermission> NOT_EXPECTED_PERMISSIONS = EnumSet.of(GROUP_READ, GROUP_WRITE, OTHERS_READ, OTHERS_WRITE);
    // "tmpdir" is used as a global well-known location for the files
    // .java_pid<pid>. and .attach_pid<pid>. It is important that this
    // location is the same for all processes, otherwise the tools
    // will not be able to find all Hotspot processes.
    // This is intentionally not the same as java.io.tmpdir, since
    // the latter can be changed by the user.
    // Any changes to this needs to be synchronized with HotSpot.
    private static final Path tmpdir;
    private static final boolean IS_MAC_OS = System.getProperty("os.name").equals("Mac OS X");
    Path socket_path;
    private UnixDomainSocketAddress socket_address;
    private OperationProperties props = new OperationProperties(VERSION_1); // updated in ctor

    /**
     * Attaches to the target VM
     */
    VirtualMachineImpl(AttachProvider provider, String vmid)
        throws AttachNotSupportedException, IOException
    {
        super(provider, vmid);

        // This provider only understands pids
        int pid = Integer.parseInt(vmid);
        if (pid < 1) {
            throw new AttachNotSupportedException("Invalid process identifier: " + vmid);
        }

        // Find the socket file. If not found then we attempt to start the
        // attach mechanism in the target VM by sending it a QUIT signal.
        // Then we attempt to find the socket file again.
        socket_path = tmpdir.resolve(".java_pid" + pid);
        if (!Files.exists(socket_path)) {
            Path f = createAttachFile(pid);
            try {
                checkCatchesAndSendQuitTo(pid, false);

                // give the target VM time to start the attach mechanism
                final int delay_step = 100;
                final long timeout = attachTimeout();
                long time_spent = 0;
                long delay = 0;

                boolean timedout = false;
                do {
                    // Increase timeout on each attempt to reduce polling
                    delay += delay_step;
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException x) { }

                    timedout = (time_spent += delay) > timeout;

                    if (time_spent > timeout/2 && !Files.exists(socket_path)) {
                        // Send QUIT again to give target VM the last chance to react
                        checkCatchesAndSendQuitTo(pid, !timedout);
                    }
                } while (!timedout && !Files.exists(socket_path));
                if (!Files.exists(socket_path)) {
                    throw new AttachNotSupportedException(
                        String.format("Unable to open socket file %s: " +
                                      "target process %d doesn't respond within %dms " +
                                      "or HotSpot VM not loaded", socket_path,
                                      pid, time_spent));
                }
            } finally {
                Files.delete(f);
            }
        }

        // Check that the file owner/permission to avoid attaching to
        // bogus process
        checkPermissions(socket_path);

        socket_address = UnixDomainSocketAddress.of(socket_path);

        if (isAPIv2Enabled()) {
            props = getDefaultProps();
        } else {
            // Check that we can connect to the process
            // - this ensures we throw the permission denied error now rather than
            // later when we attempt to enqueue a command.
            try (SocketChannel s = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                s.connect(socket_address);
            }
        }
    }

    /**
     * Detach from the target VM
     */
    public void detach() throws IOException {
        synchronized (this) {
            if (socket_path != null) {
                socket_path = null;
            }
        }
    }

    /**
     * Execute the given command in the target VM.
     */
    InputStream execute(String cmd, Object ... args) throws AgentLoadException, IOException {
        checkNulls(args);

        // did we detach?
        synchronized (this) {
            if (socket_path == null) {
                throw new IOException("Detached from target VM");
            }
        }

        // create UNIX socket
        SocketChannel s = SocketChannel.open(StandardProtocolFamily.UNIX);

        // connect to target VM
        try {
            s.connect(socket_address);
        } catch (IOException x) {
            s.close();
            throw x;
        }

        IOException ioe = null;

        // connected - write request
        try {
            SocketOutputStream writer = new SocketOutputStream(s);
            writeCommand(writer, props, cmd, args);
        } catch (IOException x) {
            ioe = x;
        }


        // Create an input stream to read reply
        InputStream sis = Channels.newInputStream(s);

        // Process the command completion status
        processCompletionStatus(ioe, cmd, sis);

        // Return the input stream so that the command output can be read
        return sis;
    }

    private static class SocketOutputStream implements AttachOutputStream {
        private final SocketChannel channel;
        public SocketOutputStream(SocketChannel channel) {
            this.channel = channel;
        }
        @Override
        public void write(byte[] buffer, int offset, int length) throws IOException {
            ByteBuffer bb = ByteBuffer.wrap(buffer, offset, length);
            channel.write(bb);
        }
    }

    private Path createAttachFile(int pid) throws IOException {
        Path attachFile = tmpdir.resolve(".attach_pid" + pid);
        Files.createFile(attachFile, PosixFilePermissions.asFileAttribute(Set.of(PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_READ)));
        return attachFile;
    }

    private static void checkPermissions(Path path) throws IOException {
        UserPrincipal processUser = UnixUserPrincipals.fromUid((int) VM.geteuid());
        GroupPrincipal processGroup = UnixUserPrincipals.fromGid((int) VM.getegid());
        
        PosixFileAttributes attributes = Files.readAttributes(path, PosixFileAttributes.class);
        UserPrincipal root = path.getFileSystem().getUserPrincipalLookupService() .lookupPrincipalByName("root");
        boolean isRoot = root.equals(processUser);

        Set<PosixFilePermission> permission = attributes.permissions();
        UserPrincipal fileOwner = attributes.owner();
        GroupPrincipal fileGroup = attributes.group();

        if (!fileOwner.equals(processUser) && !isRoot) {
            throwFileNotSecure(path,
                "file should be owned by the current user (which is " + processUser + ") but is owned by " + fileOwner);
        } else if (!fileGroup.equals(processGroup) && !isRoot) {
            throwFileNotSecure(path,
                "file's group should be the current group (which is " + fileGroup + ") but the group is " + processGroup);
        } else if (!permission.isEmpty()) {
            Set<PosixFilePermission> intersection = EnumSet.copyOf(permission);
            intersection.retainAll(NOT_EXPECTED_PERMISSIONS);
            if (!intersection.isEmpty()) {
                throwFileNotSecure(path, "file should only be readable and writable by the owner but has "
                    + PosixFilePermissions.toString( permission) + " access");
            }
        }
    }

    private static void throwFileNotSecure(Path pathSpec, String message) throws IOException {
        throw new IOException("well-known file " + pathSpec + " is not secure: " + message);
    }

    private static boolean checkCatchesAndSendQuitTo(int pid, boolean throwIfNotReady) throws IOException, AttachNotSupportedException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment mib = arena.allocateFrom(C_INT, CTL_KERN, KERN_PROC, KERN_PROC_PID, pid);
            MemorySegment kiproc = arena.allocate(kinfo_proc.layout());
            MemorySegment kipsz = arena.allocateFrom(size_t, kinfo_proc.sizeof());

            /*
             * Early in the lifetime of a JVM it has not yet initialized its signal handlers, in particular the QUIT
             * handler, note that the default behavior of QUIT is to terminate the receiving process, if unhandled.
             *
             * Since we use QUIT to initiate an attach operation, if we signal a JVM during this period early in its
             * lifetime before it has initialized its QUIT handler, such a signal delivery will terminate the JVM we
             * are attempting to attach to!
             *
             * The following code guards the QUIT delivery by testing the current signal masks. It is okay to send QUIT
             * if the signal is caught but not ignored, as that implies a handler has been installed.
             */

            if (MacOs.sysctl(mib, (int) (mib.byteSize() / C_INT.byteSize()), kiproc, kipsz, NULL, 0) == 0) {
                MemorySegment kp_proc = kinfo_proc.kp_proc(kiproc);
                MemorySegment p_sigignore = kp_proc.asSlice(extern_proc.p_sigignore$offset(), extern_proc.p_sigignore$layout());
                MemorySegment p_sigcatch = kp_proc.asSlice(extern_proc.p_sigcatch$offset(), extern_proc.p_sigcatch$layout());
                boolean ignored = sigismember(p_sigignore, SIGQUIT) != 0;
                boolean caught  = sigismember(p_sigcatch, SIGQUIT)  != 0;
                // note: obviously the masks could change between testing and signalling however this is not the
                // observed behavior of the current JVM implementation.

                if (caught && !ignored) {
                    if (kill(pid, SIGQUIT) != 0) {
                        throw new IOException("kill");
                    } else {
                        return true;
                    }
                } else if (throwIfNotReady) {
                    throw new AttachNotSupportedException("pid: " + pid + ", state is not ready to participate in attach handshake!");
                }
            } else {
                throw new IOException("sysctl");
            }

            return false;
        }
    }

    private static Path getTempDir() {
        if (IS_MAC_OS) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment buf = arena.allocate(C_CHAR, PATH_MAX);
                long pathSize = confstr(_CS_DARWIN_USER_TEMP_DIR, buf, PATH_MAX);
                if (pathSize != 0 || pathSize > PATH_MAX) {
                    // native.encoding is UTF-8 on macOS
                    // the string is NULL terminated
                    return Paths.get(buf.getString(0));
                }
            }
        }
        return Paths.get("/tmp");
    }

    static {
        tmpdir = getTempDir();
    }
}
