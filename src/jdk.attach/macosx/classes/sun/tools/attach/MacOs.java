/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
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

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

import java.lang.foreign.AddressLayout;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/*
 * FFM support class for native macOS calls.
 */
@SuppressWarnings("restricted")
final class MacOs {

    private MacOs() {
        throw new AssertionError("not instantiable");
    }


    static MemorySegment findOrThrow(String symbol) {
        return SYMBOL_LOOKUP.find(symbol)
                        .orElseThrow(() -> new UnsatisfiedLinkError("unresolved symbol: " + symbol));
    }

    private static final SymbolLookup SYMBOL_LOOKUP = SymbolLookup.loaderLookup()
                    .or(Linker.nativeLinker().defaultLookup());

    static final ValueLayout C_CHAR = ValueLayout.JAVA_BYTE;
    static final ValueLayout C_SHORT = ValueLayout.JAVA_SHORT;
    static final ValueLayout.OfInt C_INT = ValueLayout.JAVA_INT;
    static final AddressLayout C_POINTER = ValueLayout.ADDRESS
                    .withTargetLayout(MemoryLayout.sequenceLayout(Long.MAX_VALUE, JAVA_BYTE));
    static final ValueLayout.OfLong C_LONG = ValueLayout.JAVA_LONG;
    static final ValueLayout C_LONG_LONG = ValueLayout.JAVA_LONG;
    static final ValueLayout.OfLong size_t = C_LONG;

    static final int SIGQUIT = 3;
    static final int PATH_MAX = 1024;
    static final int _CS_DARWIN_USER_TEMP_DIR = 65537;
    static final int CTL_KERN = 1;
    static final int KERN_PROC = 14;
    static final int KERN_PROC_PID = 1;

    private static class confstr {

        private static final FunctionDescriptor DESC = FunctionDescriptor.of(
                        C_LONG,
                        C_INT,
                        C_POINTER,
                        C_LONG
                        );

        private static final MemorySegment ADDR = MacOs.findOrThrow("confstr");

        static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }


    /**
     * {@snippet lang=c :
     * size_t confstr(int, char *, size_t __len)
     * }
     */
    static long confstr(int x0, MemorySegment x1, long __len) {
        var mh$ = confstr.HANDLE;
        try {
            return (long) mh$.invokeExact(x0, x1, __len);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }


    private static class sysctl {
        private static final FunctionDescriptor DESC = FunctionDescriptor.of(
                        C_INT,
                        C_POINTER,
                        C_INT,
                        C_POINTER,
                        C_POINTER,
                        C_POINTER,
                        C_LONG
                        );

        private static final MemorySegment ADDR = MacOs.findOrThrow("sysctl");

        static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * {@snippet lang=c :
     * int sysctl(int *, u_int, void *, size_t *oldlenp, void *, size_t newlen)
     * }
     */
    static int sysctl(MemorySegment x0, int x1, MemorySegment x2, MemorySegment oldlenp, MemorySegment x4, long newlen) {
        var mh$ = sysctl.HANDLE;
        try {
            return (int) mh$.invokeExact(x0, x1, x2, oldlenp, x4, newlen);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class kill {
        private static final FunctionDescriptor DESC = FunctionDescriptor.of(
                        C_INT,
                        C_INT,
                        C_INT
                        );

        private static final MemorySegment ADDR = MacOs.findOrThrow("kill");

        static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * {@snippet lang=c :
     * int kill(pid_t, int)
     * }
     */
    static int kill(int x0, int x1) {
        var mh$ = kill.HANDLE;
        try {
            return (int) mh$.invokeExact(x0, x1);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class sigismember {
        private static final FunctionDescriptor DESC = FunctionDescriptor.of(
                        C_INT,
                        C_POINTER,
                        C_INT
                        );

        private static final MemorySegment ADDR = MacOs.findOrThrow("sigismember");

        static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * {@snippet lang=c :
     * int sigismember(const sigset_t *, int)
     * }
     */
    static int sigismember(MemorySegment x0, int x1) {
        var mh$ = sigismember.HANDLE;
        try {
            return (int) mh$.invokeExact(x0, x1);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

}
