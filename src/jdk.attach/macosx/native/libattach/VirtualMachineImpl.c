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

#include "jni_util.h"

#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/syslimits.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include "sun_tools_attach_VirtualMachineImpl.h"

/*
 * Declare library specific JNI_Onload entry if static build
 */
DEF_STATIC_JNI_OnLoad

/*
 * Class:     sun_tools_attach_VirtualMachineImpl
 * Method:    checkCatchesAndSendQuitTo
 * Signature: (I)V
 */
JNIEXPORT jboolean JNICALL Java_sun_tools_attach_VirtualMachineImpl_checkCatchesAndSendQuitTo
  (JNIEnv *env, jclass cls, jint pid, jboolean throwIfNotReady)
{
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid };

    struct kinfo_proc kiproc;
    size_t            kipsz = sizeof(struct kinfo_proc);

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

    if (sysctl(mib, sizeof(mib) / sizeof(int), &kiproc, &kipsz, NULL, 0) == 0) {
        const bool ignored = (kiproc.kp_proc.p_sigignore & sigmask(SIGQUIT)) != 0;
        const bool caught  = (kiproc.kp_proc.p_sigcatch & sigmask(SIGQUIT))  != 0;

        // note: obviously the masks could change between testing and signalling however this is not the
        // observed behavior of the current JVM implementation.

        if (caught && !ignored) {
            if (kill((pid_t)pid, SIGQUIT) != 0) {
                JNU_ThrowIOExceptionWithLastError(env, "kill");
            } else {
                return JNI_TRUE;
            }
        } else if (throwIfNotReady) {
            char msg[100];

            snprintf(msg, sizeof(msg), "pid: %d, state is not ready to participate in attach handshake!", (int)pid);

            JNU_ThrowByName(env, "com/sun/tools/attach/AttachNotSupportedException", msg);
        }
    } else {
        JNU_ThrowIOExceptionWithLastError(env, "sysctl");
    }

    return JNI_FALSE;
}

/*
 * Class:     sun_tools_attach_BSDVirtualMachine
 * Method:    getTempDir
 * Signature: (V)Ljava.lang.String;
 */
JNIEXPORT jstring JNICALL Java_sun_tools_attach_VirtualMachineImpl_getTempDir(JNIEnv *env, jclass cls)
{
    // This must be hard coded because it's the system's temporary
    // directory not the java application's temp directory, ala java.io.tmpdir.

#ifdef __APPLE__
    // macosx has a secure per-user temporary directory.
    // Don't cache the result as this is only called once.
    char path[PATH_MAX];
    int pathSize = confstr(_CS_DARWIN_USER_TEMP_DIR, path, PATH_MAX);
    if (pathSize == 0 || pathSize > PATH_MAX) {
        strlcpy(path, "/tmp", sizeof(path));
    }
    return JNU_NewStringPlatform(env, path);
#else /* __APPLE__ */
    return (*env)->NewStringUTF(env, "/tmp");
#endif /* __APPLE__ */
}
