/*
 * Copyright (c) 2008, 2025, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, 2019 SAP SE. All rights reserved.
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

import java.io.InputStream;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;

/*
 * Aix implementation of HotSpotVirtualMachine
 */
@SuppressWarnings("restricted")
public class VirtualMachineImpl extends HotSpotVirtualMachine {
    // "/tmp" is used as a global well-known location for the files
    // .java_pid<pid>. and .attach_pid<pid>. It is important that this
    // location is the same for all processes, otherwise the tools
    // will not be able to find all Hotspot processes.
    // Any changes to this needs to be synchronized with HotSpot.
    private static final Path TMPDIR = Path.of("/tmp");

    private static final Path PROC     = Path.of("/proc");

    private static final long ROOT_UID = 0L;
    private static final int S_IRGRP = 0040;
    private static final int S_IWGRP = 0020;
    private static final int S_IROTH = 0004;
    private static final int S_IWOTH = 002;

    Path socket_path;
    private SocketAddress socket_address;
    private OperationProperties props = new OperationProperties(VERSION_1);
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
        Path socket_file = TMPDIR.resolve(".java_pid" + pid);
        socket_path = socket_file;
        if (!Files.exists(socket_file)) {
            // Keep canonical version of File, to delete, in case target process ends and /proc link has gone:
            Path f = createAttachFile(pid).toRealPath();
            try {
                sendQuitTo(pid);

                // give the target VM time to start the attach mechanism
                final int delay_step = 100;
                final long timeout = attachTimeout();
                long time_spent = 0;
                long delay = 0;
                do {
                    // Increase timeout on each attempt to reduce polling
                    delay += delay_step;
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException x) { }

                    time_spent += delay;
                    if (time_spent > timeout/2 && !Files.exists(socket_file)) {
                        // Send QUIT again to give target VM the last chance to react
                        sendQuitTo(pid);
                    }
                } while (time_spent <= timeout && !Files.exists(socket_file));
                if (!Files.exists(socket_file)) {
                    throw new AttachNotSupportedException(
                        String.format("Unable to open socket file %s: " +
                          "target process %d doesn't respond within %dms " +
                           "or HotSpot VM not loaded", socket_path, pid,
                                      time_spent));
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
        // <ver> <cmd> <args...>
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

    // On Aix a simple handshake is used to start the attach mechanism
    // if not already started. The client creates a .attach_pid<pid> file in the
    // target VM's working directory (or temp directory), and the SIGQUIT handler
    // checks for the file.
    private static Path createAttachFile(int pid) throws IOException {
      Path fn   = Path.of(".attach_pid" + pid);
        Path path = PROC.resolve(Integer.toString(pid)).resolve("cwd").resolve(fn);
        try {
            Files.createFile(path);
        } catch (FileAlreadyExistsException _) {
            path = TMPDIR.resolve(fn);
            Files.createFile(path);
        }
        return path;
    }

    private static void checkPermissions(Path path) throws IOException {
        long processUid = VM.geteuid();
        long processGid = VM.getegid();
        Map<String, Object> attributes = Files.readAttributes(path, "unix:uid,gid,mode");
        int fileUid = (int) attributes.get("uid");
        int fileGid = (int) attributes.get("gid");
        int mode = (int) attributes.get("mode");
        if (fileUid != processUid && processUid != ROOT_UID) {
            throwFileNotSecure(path, "file should be owned by the current user (which is " + processUid + ") but is owned by " + fileUid);
        } else if (fileGid != processGid && processUid != ROOT_UID) {
            throwFileNotSecure(path, "file's group should be the current group (which is " + processGid + ") but the group is " + fileGid);
        } else if ((mode & (S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) != 0) {
            throwFileNotSecure(path, "file should only be readable and writable by the owner but has " + String.format("0%03o", mode & 0777) + " access");
        }
    }

    private static void throwFileNotSecure(Path pathSpec, String message) throws IOException {
        throw new IOException("well-known file " + pathSpec + " is not secure: " + message);
    }

    //-- native methods

    static native void sendQuitTo(int pid) throws IOException;

    static {
        System.loadLibrary("attach");
    }
}
