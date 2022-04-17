/*
 * Copyright (c) 2005, 2022, Oracle and/or its affiliates. All rights reserved.
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

import com.sun.tools.attach.AttachOperationFailedException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.spi.AttachProvider;

import jdk.internal.misc.VM;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.net.SocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/*
 * Linux implementation of HotSpotVirtualMachine
 */
public class VirtualMachineImpl extends HotSpotVirtualMachine {
    // "/tmp" is used as a global well-known location for the files
    // .java_pid<pid>. and .attach_pid<pid>. It is important that this
    // location is the same for all processes, otherwise the tools
    // will not be able to find all Hotspot processes.
    // Any changes to this needs to be synchronized with HotSpot.
    private static final String tmpdir = "/tmp";

    private static final long ROOT_UID = 0L;
    private static final int S_IRGRP = 0040;
    private static final int S_IWGRP = 0020;
    private static final int S_IROTH = 0004;
    private static final int S_IWOTH = 002;

    String socket_path;

    private final SocketAddress socket_address;

    /**
     * Attaches to the target VM
     */
    VirtualMachineImpl(AttachProvider provider, String vmid)
        throws AttachNotSupportedException, IOException
    {
        super(provider, vmid);

        // This provider only understands pids
        int pid;
        try {
            pid = Integer.parseInt(vmid);
            if (pid < 1) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException x) {
            throw new AttachNotSupportedException("Invalid process identifier: " + vmid);
        }

        // Try to resolve to the "inner most" pid namespace
        int ns_pid = getNamespacePid(pid);

        // Find the socket file. If not found then we attempt to start the
        // attach mechanism in the target VM by sending it a QUIT signal.
        // Then we attempt to find the socket file again.
        File socket_file = findSocketFile(pid, ns_pid);
        socket_path = socket_file.getPath();
        if (!socket_file.exists()) {
            // Keep canonical version of File, to delete, in case target process ends and /proc link has gone:
            File f = createAttachFile(pid, ns_pid).getCanonicalFile();
            try {
                sendQuitTo(pid);

                // give the target VM time to start the attach mechanism
                final int delay_step = 100;
                final long timeout = attachTimeout();
                long time_spend = 0;
                long delay = 0;
                do {
                    // Increase timeout on each attempt to reduce polling
                    delay += delay_step;
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException x) { }

                    time_spend += delay;
                    if (time_spend > timeout/2 && !socket_file.exists()) {
                        // Send QUIT again to give target VM the last chance to react
                        sendQuitTo(pid);
                    }
                } while (time_spend <= timeout && !socket_file.exists());
                if (!socket_file.exists()) {
                    throw new AttachNotSupportedException(
                        String.format("Unable to open socket file %s: " +
                          "target process %d doesn't respond within %dms " +
                          "or HotSpot VM not loaded", socket_path, pid,
                                      time_spend));
                }
            } finally {
                f.delete();
            }
        }

        // Check that the file owner/permission to avoid attaching to
        // bogus process
        checkPermissions(socket_path);

        socket_address = UnixDomainSocketAddress.of(socket_path);
        // Check that we can connect to the process
        // - this ensures we throw the permission denied error now rather than
        // later when we attempt to enqueue a command.
        try (SocketChannel s = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            s.connect(socket_address);
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

    // protocol version
    private static final String PROTOCOL_VERSION = "1";

    // known errors
    private static final int ATTACH_ERROR_BADVERSION = 101;

    /**
     * Execute the given command in the target VM.
     */
    InputStream execute(String cmd, Object ... args) throws AgentLoadException, IOException {
        assert args.length <= 3;                // includes null

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
            writeString(s, PROTOCOL_VERSION);
            writeString(s, cmd);

            for (int i = 0; i < 3; i++) {
                if (i < args.length && args[i] != null) {
                    writeString(s, (String)args[i]);
                } else {
                    writeString(s, "");
                }
            }
        } catch (IOException x) {
            ioe = x;
        }


        // Create an input stream to read reply
        InputStream sis = Channels.newInputStream(s);

        // Read the command completion status
        int completionStatus;
        try {
            completionStatus = readInt(sis);
        } catch (IOException x) {
            sis.close();
            if (ioe != null) {
                throw ioe;
            } else {
                throw x;
            }
        }

        if (completionStatus != 0) {
            // read from the stream and use that as the error message
            String message = readErrorMessage(sis);
            sis.close();

            // In the event of a protocol mismatch then the target VM
            // returns a known error so that we can throw a reasonable
            // error.
            if (completionStatus == ATTACH_ERROR_BADVERSION) {
                throw new IOException("Protocol mismatch with target VM");
            }

            // Special-case the "load" command so that the right exception is
            // thrown.
            if (cmd.equals("load")) {
                String msg = "Failed to load agent library";
                if (!message.isEmpty())
                    msg += ": " + message;
                throw new AgentLoadException(msg);
            } else {
                if (message.isEmpty())
                    message = "Command failed in target VM";
                throw new AttachOperationFailedException(message);
            }
        }

        // Return the input stream so that the command output can be read
        return sis;
    }

    // Return the socket file for the given process.
    private File findSocketFile(int pid, int ns_pid) {
        // A process may not exist in the same mount namespace as the caller.
        // Instead, attach relative to the target root filesystem as exposed by
        // procfs regardless of namespaces.
        String root = "/proc/" + pid + "/root/" + tmpdir;
        return new File(root, ".java_pid" + ns_pid);
    }

    // On Linux a simple handshake is used to start the attach mechanism
    // if not already started. The client creates a .attach_pid<pid> file in the
    // target VM's working directory (or temp directory), and the SIGQUIT handler
    // checks for the file.
    private File createAttachFile(int pid, int ns_pid) throws IOException {
        String fn = ".attach_pid" + ns_pid;
        String path = "/proc/" + pid + "/cwd/" + fn;
        File f = new File(path);
        try {
            // Do not canonicalize the file path, or we will fail to attach to a VM in a container.
            f.createNewFile();
        } catch (IOException x) {
            String root;
            if (pid != ns_pid) {
                // A process may not exist in the same mount namespace as the caller.
                // Instead, attach relative to the target root filesystem as exposed by
                // procfs regardless of namespaces.
                root = "/proc/" + pid + "/root/" + tmpdir;
            } else {
                root = tmpdir;
            }
            f = new File(root, fn);
            f.createNewFile();
        }
        return f;
    }

    /*
     * Write/sends the given to the target VM. String is transmitted in
     * UTF-8 encoding.
     */
    private void writeString(WritableByteChannel channel, String s) throws IOException {
        if (!s.isEmpty()) {
            channel.write(ByteBuffer.wrap(s.getBytes(UTF_8)));
        }
        channel.write(ByteBuffer.wrap(new byte[]{0x00}));
    }


    // Return the inner most namespaced PID if there is one,
    // otherwise return the original PID.
    private int getNamespacePid(int pid) throws AttachNotSupportedException, IOException {
        // Assuming a real procfs sits beneath, reading this doesn't block
        // nor will it consume a lot of memory.
        String statusFile = "/proc/" + pid + "/status";
        File f = new File(statusFile);
        if (!f.exists()) {
            return pid; // Likely a bad pid, but this is properly handled later.
        }

        Path statusPath = Paths.get(statusFile);

        try {
            for (String line : Files.readAllLines(statusPath)) {
                String[] parts = line.split(":");
                if (parts.length == 2 && parts[0].trim().equals("NSpid")) {
                    parts = parts[1].trim().split("\\s+");
                    // The last entry represents the PID the JVM "thinks" it is.
                    // Even in non-namespaced pids these entries should be
                    // valid. You could refer to it as the inner most pid.
                    int ns_pid = Integer.parseInt(parts[parts.length - 1]);
                    return ns_pid;
                }
            }
            // Old kernels may not have NSpid field (i.e. 3.10).
            // Fallback to original pid in the event we cannot deduce.
            return pid;
        } catch (NumberFormatException | IOException x) {
            throw new AttachNotSupportedException("Unable to parse namespace");
        }
    }

    private static void checkPermissions(String pathSpec) throws IOException {
        Path path = Path.of(pathSpec);
        long processUid = VM.geteuid();
        long processGid = VM.getegid();
        Map<String, Object> attributes = Files.readAttributes(path, "unix:uid,gid,mode");
        int fileUid = (int) attributes.get("uid");
        int fileGid = (int) attributes.get("gid");
        int mode = (int) attributes.get("mode");
        if (fileUid != processUid && processUid != ROOT_UID) {
            throwFileNotSecure(pathSpec, "file should be owned by the current user (which is " + processUid + ") but is owned by " + fileUid);
        } else if (fileGid != processGid && processUid != ROOT_UID) {
            throwFileNotSecure(pathSpec, "file's group should be the current group (which is " + processGid + ") but the group is " + fileGid);
        } else if ((mode & (S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) != 0) {
            throwFileNotSecure(pathSpec, "file should only be readable and writable by the owner but has " + String.format("0%03o", mode & 0777) + " access");
        }
    }

    private static void throwFileNotSecure(String pathSpec, String message) throws IOException {
        throw new IOException("well-known file " + pathSpec + " is not secure: " + message);
    }

    //-- native methods

    // ProcessHandle.of(pid).orElseThrow(() -> new IOException("kill")).destroy();
    static native void sendQuitTo(int pid) throws IOException;

    static {
        System.loadLibrary("attach");
    }
}
