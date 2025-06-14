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

import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static sun.tools.attach.MacOs.C_CHAR;
import static sun.tools.attach.MacOs.C_INT;
import static sun.tools.attach.MacOs.C_LONG;
import static sun.tools.attach.MacOs.C_LONG_LONG;
import static sun.tools.attach.MacOs.C_POINTER;
import static sun.tools.attach.MacOs.C_SHORT;

import java.lang.foreign.GroupLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout.OfInt;

/**
 * {@snippet lang=c :
 * struct extern_proc {
 *     union {
 *         struct {
 *             struct proc *__p_forw;
 *             struct proc *__p_back;
 *         } p_st1;
 *         struct timeval __p_starttime;
 *     } p_un;
 *     struct vmspace *p_vmspace;
 *     struct sigacts *p_sigacts;
 *     int p_flag;
 *     char p_stat;
 *     pid_t p_pid;
 *     pid_t p_oppid;
 *     int p_dupfd;
 *     caddr_t user_stack;
 *     void *exit_thread;
 *     int p_debugger;
 *     boolean_t sigwait;
 *     u_int p_estcpu;
 *     int p_cpticks;
 *     fixpt_t p_pctcpu;
 *     void *p_wchan;
 *     char *p_wmesg;
 *     u_int p_swtime;
 *     u_int p_slptime;
 *     struct itimerval p_realtimer;
 *     struct timeval p_rtime;
 *     u_quad_t p_uticks;
 *     u_quad_t p_sticks;
 *     u_quad_t p_iticks;
 *     int p_traceflag;
 *     struct vnode *p_tracep;
 *     int p_siglist;
 *     struct vnode *p_textvp;
 *     int p_holdcnt;
 *     sigset_t p_sigmask;
 *     sigset_t p_sigignore;
 *     sigset_t p_sigcatch;
 *     u_char p_priority;
 *     u_char p_usrpri;
 *     char p_nice;
 *     char p_comm[17];
 *     struct pgrp *p_pgrp;
 *     struct user *p_addr;
 *     u_short p_xstat;
 *     u_short p_acflag;
 *     struct rusage *p_ru;
 * }
 * }
 */
final class extern_proc {

    extern_proc() {
      throw new AssertionError("not instantiable");
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        extern_proc.p_un.layout().withName("p_un"),
        C_POINTER.withName("p_vmspace"),
        C_POINTER.withName("p_sigacts"),
        C_INT.withName("p_flag"),
        C_CHAR.withName("p_stat"),
        MemoryLayout.paddingLayout(3),
        C_INT.withName("p_pid"),
        C_INT.withName("p_oppid"),
        C_INT.withName("p_dupfd"),
        MemoryLayout.paddingLayout(4),
        C_POINTER.withName("user_stack"),
        C_POINTER.withName("exit_thread"),
        C_INT.withName("p_debugger"),
        C_INT.withName("sigwait"),
        C_INT.withName("p_estcpu"),
        C_INT.withName("p_cpticks"),
        C_INT.withName("p_pctcpu"),
        MemoryLayout.paddingLayout(4),
        C_POINTER.withName("p_wchan"),
        C_POINTER.withName("p_wmesg"),
        C_INT.withName("p_swtime"),
        C_INT.withName("p_slptime"),
        itimerval.layout().withName("p_realtimer"),
        timeval.layout().withName("p_rtime"),
        C_LONG_LONG.withName("p_uticks"),
        C_LONG_LONG.withName("p_sticks"),
        C_LONG_LONG.withName("p_iticks"),
        C_INT.withName("p_traceflag"),
        MemoryLayout.paddingLayout(4),
        C_POINTER.withName("p_tracep"),
        C_INT.withName("p_siglist"),
        MemoryLayout.paddingLayout(4),
        C_POINTER.withName("p_textvp"),
        C_INT.withName("p_holdcnt"),
        C_INT.withName("p_sigmask"),
        C_INT.withName("p_sigignore"),
        C_INT.withName("p_sigcatch"),
        C_CHAR.withName("p_priority"),
        C_CHAR.withName("p_usrpri"),
        C_CHAR.withName("p_nice"),
        MemoryLayout.sequenceLayout(17, C_CHAR).withName("p_comm"),
        MemoryLayout.paddingLayout(4),
        C_POINTER.withName("p_pgrp"),
        C_POINTER.withName("p_addr"),
        C_SHORT.withName("p_xstat"),
        C_SHORT.withName("p_acflag"),
        MemoryLayout.paddingLayout(4),
        C_POINTER.withName("p_ru")
    ).withName("extern_proc");

    /**
     * The layout of this struct
     */
    static final GroupLayout layout() {
        return $LAYOUT;
    }
    
    /**
     * {@snippet lang=c :
     * struct itimerval {
     *     struct timeval it_interval;
     *     struct timeval it_value;
     * }
     * }
     */
    static final class itimerval {

        /**
         * The layout of this struct
         */
        static final GroupLayout layout() {
            return MemoryLayout.structLayout(
                timeval.layout().withName("it_interval"),
                timeval.layout().withName("it_value")
            ).withName("itimerval");
        }
    }
    
    /**
     * {@snippet lang=c :
     * struct timeval {
     *     __darwin_time_t tv_sec;
     *     __darwin_suseconds_t tv_usec;
     * }
     * }
     */
    static final class timeval {

        /**
         * The layout of this struct
         */
        static final GroupLayout layout() {
            return MemoryLayout.structLayout(
                C_LONG.withName("tv_sec"),
                C_INT.withName("tv_usec"),
                MemoryLayout.paddingLayout(4)
            ).withName("timeval");
        }

    }

    /**
     * {@snippet lang=c :
     * union {
     *     struct {
     *         struct proc *__p_forw;
     *         struct proc *__p_back;
     *     } p_st1;
     *     struct timeval __p_starttime;
     * }
     * }
     */
    final static class p_un {

        static final GroupLayout layout() {
            return MemoryLayout.unionLayout(
                extern_proc.p_un.p_st1.layout().withName("p_st1"),
                timeval.layout().withName("__p_starttime")
            ).withName("$anon$92:2");
        }

        /**
         * {@snippet lang=c :
         * struct {
         *     struct proc *__p_forw;
         *     struct proc *__p_back;
         * }
         * }
         */
        static final class p_st1 {

            private p_st1() {
              throw new AssertionError("not instantiable");
            }

            static final GroupLayout layout() {
                return MemoryLayout.structLayout(
                    C_POINTER.withName("__p_forw"),
                    C_POINTER.withName("__p_back")
                ).withName("$anon$93:3");
            }

        }

    }


    private static final OfInt p_sigignore$LAYOUT = (OfInt)$LAYOUT.select(groupElement("p_sigignore"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * sigset_t p_sigignore
     * }
     */
    static final OfInt p_sigignore$layout() {
        return p_sigignore$LAYOUT;
    }

    private static final long p_sigignore$OFFSET = 232;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * sigset_t p_sigignore
     * }
     */
    static final long p_sigignore$offset() {
        return p_sigignore$OFFSET;
    }

    private static final OfInt p_sigcatch$LAYOUT = (OfInt)$LAYOUT.select(groupElement("p_sigcatch"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * sigset_t p_sigcatch
     * }
     */
    static final OfInt p_sigcatch$layout() {
        return p_sigcatch$LAYOUT;
    }

    private static final long p_sigcatch$OFFSET = 236;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * sigset_t p_sigcatch
     * }
     */
    static final long p_sigcatch$offset() {
        return p_sigcatch$OFFSET;
    }

}

