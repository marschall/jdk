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
import static sun.tools.attach.MacOs.C_POINTER;
import static sun.tools.attach.MacOs.C_SHORT;

import java.lang.foreign.GroupLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;

/**
 * {@snippet lang=c :
 * struct kinfo_proc {
 *     struct extern_proc kp_proc;
 *     struct eproc {
 *         struct proc *e_paddr;
 *         struct session *e_sess;
 *         struct _pcred e_pcred;
 *         struct _ucred e_ucred;
 *         struct vmspace e_vm;
 *         pid_t e_ppid;
 *         pid_t e_pgid;
 *         short e_jobc;
 *         dev_t e_tdev;
 *         pid_t e_tpgid;
 *         struct session *e_tsess;
 *         char e_wmesg[8];
 *         segsz_t e_xsize;
 *         short e_xrssize;
 *         short e_xccount;
 *         short e_xswrss;
 *         int32_t e_flag;
 *         char e_login[12];
 *         int32_t e_spare[4];
 *     } kp_eproc;
 * }
 * }
 */
final class kinfo_proc {

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        extern_proc.layout().withName("kp_proc"),
        kinfo_proc.eproc.layout().withName("kp_eproc")
    ).withName("kinfo_proc");

    static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final GroupLayout kp_proc$LAYOUT = (GroupLayout)$LAYOUT.select(groupElement("kp_proc"));

    private static final long kp_proc$OFFSET = 0;

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct extern_proc kp_proc
     * }
     */
    static MemorySegment kp_proc(MemorySegment struct) {
        return struct.asSlice(kp_proc$OFFSET, kp_proc$LAYOUT.byteSize());
    }
    
    /**
     * {@snippet lang=c :
     * struct vmspace {
     *     int32_t dummy;
     *     caddr_t dummy2;
     *     int32_t dummy3[5];
     *     caddr_t dummy4[3];
     * }
     * }
     */
    static class vmspace {

        /**
         * The layout of this struct
         */
        static final GroupLayout layout() {
            return MemoryLayout.structLayout(
                C_INT.withName("dummy"),
                MemoryLayout.paddingLayout(4),
                C_POINTER.withName("dummy2"),
                MemoryLayout.sequenceLayout(5, C_INT).withName("dummy3"),
                MemoryLayout.paddingLayout(4),
                MemoryLayout.sequenceLayout(3, C_POINTER).withName("dummy4")
            ).withName("vmspace");
        }

    }
    
    /**
     * {@snippet lang=c :
     * struct _ucred {
     *     int32_t cr_ref;
     *     uid_t cr_uid;
     *     short cr_ngroups;
     *     gid_t cr_groups[16];
     * }
     * }
     */
    static final class _ucred {

        /**
         * The layout of this struct
         */
        static final GroupLayout layout() {
            return MemoryLayout.structLayout(
                C_INT.withName("cr_ref"),
                C_INT.withName("cr_uid"),
                C_SHORT.withName("cr_ngroups"),
                MemoryLayout.paddingLayout(2),
                MemoryLayout.sequenceLayout(16, C_INT).withName("cr_groups")
            ).withName("_ucred");
        }

    }
    

    /**
     * {@snippet lang=c :
     * struct _pcred {
     *     char pc_lock[72];
     *     struct ucred *pc_ucred;
     *     uid_t p_ruid;
     *     uid_t p_svuid;
     *     gid_t p_rgid;
     *     gid_t p_svgid;
     *     int p_refcnt;
     * }
     * }
     */
    static final class _pcred {

      static final GroupLayout layout() {
        return MemoryLayout.structLayout(
            MemoryLayout.sequenceLayout(72, C_CHAR).withName("pc_lock"),
            C_POINTER.withName("pc_ucred"),
            C_INT.withName("p_ruid"),
            C_INT.withName("p_svuid"),
            C_INT.withName("p_rgid"),
            C_INT.withName("p_svgid"),
            C_INT.withName("p_refcnt"),
            MemoryLayout.paddingLayout(4)
            ).withName("_pcred");
      }
    }


    /**
     * {@snippet lang=c :
     * struct eproc {
     *     struct proc *e_paddr;
     *     struct session *e_sess;
     *     struct _pcred e_pcred;
     *     struct _ucred e_ucred;
     *     struct vmspace e_vm;
     *     pid_t e_ppid;
     *     pid_t e_pgid;
     *     short e_jobc;
     *     dev_t e_tdev;
     *     pid_t e_tpgid;
     *     struct session *e_tsess;
     *     char e_wmesg[8];
     *     segsz_t e_xsize;
     *     short e_xrssize;
     *     short e_xccount;
     *     short e_xswrss;
     *     int32_t e_flag;
     *     char e_login[12];
     *     int32_t e_spare[4];
     * }
     * }
     */
    static final class eproc {

        static final GroupLayout layout() {
            return MemoryLayout.structLayout(
                C_POINTER.withName("e_paddr"),
                C_POINTER.withName("e_sess"),
                _pcred.layout().withName("e_pcred"),
                _ucred.layout().withName("e_ucred"),
                MemoryLayout.paddingLayout(4),
                vmspace.layout().withName("e_vm"),
                C_INT.withName("e_ppid"),
                C_INT.withName("e_pgid"),
                C_SHORT.withName("e_jobc"),
                MemoryLayout.paddingLayout(2),
                C_INT.withName("e_tdev"),
                C_INT.withName("e_tpgid"),
                MemoryLayout.paddingLayout(4),
                C_POINTER.withName("e_tsess"),
                MemoryLayout.sequenceLayout(8, C_CHAR).withName("e_wmesg"),
                C_INT.withName("e_xsize"),
                C_SHORT.withName("e_xrssize"),
                C_SHORT.withName("e_xccount"),
                C_SHORT.withName("e_xswrss"),
                MemoryLayout.paddingLayout(2),
                C_INT.withName("e_flag"),
                MemoryLayout.sequenceLayout(12, C_CHAR).withName("e_login"),
                MemoryLayout.sequenceLayout(4, C_INT).withName("e_spare"),
                MemoryLayout.paddingLayout(4)
            ).withName("eproc");
        }

    }

    /**
     * The size (in bytes) of this struct
     */
    static long sizeof() {
      return layout().byteSize();
    }

}

