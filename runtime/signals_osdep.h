/**************************************************************************/
/*                                                                        */
/*                                 OCaml                                  */
/*                                                                        */
/*             Xavier Leroy, projet Cristal, INRIA Rocquencourt           */
/*                                                                        */
/*   Copyright 2004 Institut National de Recherche en Informatique et     */
/*     en Automatique.                                                    */
/*                                                                        */
/*   All rights reserved.  This file is distributed under the terms of    */
/*   the GNU Lesser General Public License version 2.1, with the          */
/*   special exception on linking described in the file LICENSE.          */
/*                                                                        */
/**************************************************************************/

/* Processor- and OS-dependent signal interface */

/****************** AMD64, Linux */

#if defined(TARGET_amd64) && defined (SYS_linux)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
     sigact.sa_flags = SA_SIGINFO

  typedef greg_t context_reg;
  #define CONTEXT_C_ARG_1 (context->uc_mcontext.gregs[REG_RDI])
  #define CONTEXT_PC (context->uc_mcontext.gregs[REG_RIP])
  #define CONTEXT_SP (context->uc_mcontext.gregs[REG_RSP])
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.gregs[REG_R15])
  #define CONTEXT_FAULTING_ADDRESS ((char *)context->uc_mcontext.gregs[REG_CR2])

/****************** AMD64, MacOSX */

#elif defined(TARGET_amd64) && defined (SYS_macosx) && false

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, void * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (name); \
     sigact.sa_flags = SA_SIGINFO | SA_64REGSET

  #include <sys/ucontext.h>
  #include <AvailabilityMacros.h>

  #if (!defined(MAC_OS_X_VERSION_10_5)                            \
       || MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_5)  \
      && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    #define CONTEXT_REG(r) r
  #else
    #define CONTEXT_REG(r) __##r
  #endif

  typedef unsigned long long context_reg;
  #define CONTEXT_STATE (((ucontext_t *)context)->uc_mcontext->CONTEXT_REG(ss))
  #define CONTEXT_C_ARG_1 (CONTEXT_STATE.CONTEXT_REG(rdi))
  #define CONTEXT_PC (CONTEXT_STATE.CONTEXT_REG(rip))
  #define CONTEXT_YOUNG_PTR (CONTEXT_STATE.CONTEXT_REG(r15))
  #define CONTEXT_SP (CONTEXT_STATE.CONTEXT_REG(rsp))
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

  #define RETURN_AFTER_STACK_OVERFLOW

/****************** ARM, Linux */

#elif defined(TARGET_arm) && (defined(SYS_linux_eabi) \
      || defined(SYS_linux_eabihf))

  #include <sys/ucontext.h>

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
     sigact.sa_flags = SA_SIGINFO

  typedef unsigned long context_reg;
  #define CONTEXT_PC (context->uc_mcontext.arm_pc)
  #define CONTEXT_SP (context->uc_mcontext.arm_sp)
  #define CONTEXT_EXCEPTION_POINTER (context->uc_mcontext.arm_fp)
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.arm_r8)
  #define CONTEXT_FAULTING_ADDRESS ((char *) context->uc_mcontext.fault_address)

/****************** ARM64, Linux */

#elif defined(TARGET_arm64) && defined(SYS_linux)

  #include <sys/ucontext.h>

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
     sigact.sa_flags = SA_SIGINFO

  typedef unsigned long context_reg;
  #define CONTEXT_PC (context->uc_mcontext.pc)
  #define CONTEXT_SP (context->uc_mcontext.sp)
  #define CONTEXT_EXCEPTION_POINTER (context->uc_mcontext.regs[26])
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.regs[27])
  #define CONTEXT_FAULTING_ADDRESS ((char *) context->uc_mcontext.fault_address)

/****************** ARM64, FreeBSD */

#elif defined(TARGET_arm64) && defined(SYS_freebsd)

  #include <sys/ucontext.h>

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
     sigact.sa_flags = SA_SIGINFO

  typedef unsigned long context_reg;
  #define CONTEXT_PC (context->uc_mcontext.mc_gpregs.gp_elr)
  #define CONTEXT_SP (context->uc_mcontext.mc_gpregs.gp_sp)
  #define CONTEXT_EXCEPTION_POINTER (context->uc_mcontext.mc_gpregs.gp_x[26])
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.mc_gpregs.gp_x[27])
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)


/****************** AMD64, Solaris x86 */

#elif defined(TARGET_amd64) && defined (SYS_solaris)

  #include <ucontext.h>

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
    sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
    sigact.sa_flags = SA_SIGINFO

  typedef greg_t context_reg;
  #define CONTEXT_PC (context->uc_mcontext.gregs[REG_RIP])
  #define CONTEXT_C_ARG_1 (context->uc_mcontext.gregs[REG_RDI])
  #define CONTEXT_SP (context->uc_mcontext.gregs[REG_RSP])
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.gregs[REG_R15])
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** AMD64, OpenBSD */

#elif defined(TARGET_amd64) && defined (SYS_openbsd)

 #define DECLARE_SIGNAL_HANDLER(name) \
 static void name(int sig, siginfo_t * info, struct sigcontext * context)

 #define SET_SIGACT(sigact,name) \
 sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
 sigact.sa_flags = SA_SIGINFO

 #define CONTEXT_PC (context->sc_rip)
 #define CONTEXT_C_ARG_1 (context->sc_rdi)
 #define CONTEXT_SP (context->sc_rsp)
 #define CONTEXT_YOUNG_PTR (context->sc_r15)
 #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** AMD64, NetBSD */

#elif defined(TARGET_amd64) && defined (SYS_netbsd)

 #include <ucontext.h>
 #define DECLARE_SIGNAL_HANDLER(name) \
 static void name(int sig, siginfo_t * info, ucontext_t * context)

 #define SET_SIGACT(sigact,name) \
 sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
 sigact.sa_flags = SA_SIGINFO

 #define CONTEXT_PC (_UC_MACHINE_PC(context))
 #define CONTEXT_C_ARG_1 (context->uc_mcontext.gregs[REG_RDI])
 #define CONTEXT_SP (_UC_MACHINE_SP(context))
 #define CONTEXT_YOUNG_PTR (context->uc_mcontext.gregs[REG_R15])
 #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** I386, Linux */

#elif defined(TARGET_i386) && defined(SYS_linux_elf)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
     sigact.sa_flags = SA_SIGINFO

  typedef greg_t context_reg;
  #define CONTEXT_PC (context->uc_mcontext.gregs[REG_EIP])
  #define CONTEXT_SP (context->uc_mcontext.gregs[REG_ESP])
  #define CONTEXT_FAULTING_ADDRESS ((char *)context->uc_mcontext.cr2)

/****************** I386, BSD_ELF */

#elif defined(TARGET_i386) && defined(SYS_bsd_elf)

 #if defined (__NetBSD__)
  #include <ucontext.h>
  #define DECLARE_SIGNAL_HANDLER(name) \
  static void name(int sig, siginfo_t * info, ucontext_t * context)
 #else
  #define DECLARE_SIGNAL_HANDLER(name) \
  static void name(int sig, siginfo_t * info, struct sigcontext * context)
 #endif

 #define SET_SIGACT(sigact,name) \
 sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
 sigact.sa_flags = SA_SIGINFO

 #if defined (__NetBSD__)
  #define CONTEXT_PC (_UC_MACHINE_PC(context))
  #define CONTEXT_SP (_UC_MACHINE_SP(context))
 #else
  #define CONTEXT_PC (context->sc_eip)
  #define CONTEXT_SP (context->sc_esp)
 #endif
 #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** I386, BSD */

#elif defined(TARGET_i386) && defined(SYS_bsd)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, void * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (name); \
     sigact.sa_flags = SA_SIGINFO

  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** I386, MacOS X */

#elif defined(TARGET_i386) && defined(SYS_macosx)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, void * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (name); \
     sigact.sa_flags = SA_SIGINFO

  #include <sys/ucontext.h>
  #include <AvailabilityMacros.h>

  #if (!defined(MAC_OS_X_VERSION_10_5)                            \
       || MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_5)  \
      && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    #define CONTEXT_REG(r) r
  #else
    #define CONTEXT_REG(r) __##r
  #endif

  #define CONTEXT_STATE (((ucontext_t *)context)->uc_mcontext->CONTEXT_REG(ss))
  #define CONTEXT_PC (CONTEXT_STATE.CONTEXT_REG(eip))
  #define CONTEXT_SP (CONTEXT_STATE.CONTEXT_REG(esp))
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** I386, Solaris x86 */

#elif defined(TARGET_i386) && defined(SYS_solaris)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, void * context)

  #define SET_SIGACT(sigact,name) \
    sigact.sa_sigaction = (name); \
    sigact.sa_flags = SA_SIGINFO

  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** PowerPC, MacOS X */

#elif defined(TARGET_power) && defined(SYS_rhapsody)

  #define DECLARE_SIGNAL_HANDLER(name) \
     static void name(int sig, siginfo_t * info, void * context)

  #include <sys/ucontext.h>
  #include <AvailabilityMacros.h>

  #ifdef __LP64__
    #define SET_SIGACT(sigact,name) \
       sigact.sa_sigaction = (name); \
       sigact.sa_flags = SA_SIGINFO | SA_64REGSET

    typedef unsigned long long context_reg;

    #define CONTEXT_MCONTEXT (((ucontext64_t *)context)->uc_mcontext64)
  #else
    #define SET_SIGACT(sigact,name) \
       sigact.sa_sigaction = (name); \
       sigact.sa_flags = SA_SIGINFO

    typedef unsigned long context_reg;

    #define CONTEXT_MCONTEXT (((ucontext_t *)context)->uc_mcontext)
  #endif

  #if !defined(MAC_OS_X_VERSION_10_5) \
      || MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_5
    #define CONTEXT_REG(r) r
  #else
    #define CONTEXT_REG(r) __##r
  #endif

  #define CONTEXT_STATE (CONTEXT_MCONTEXT->CONTEXT_REG(ss))
  #define CONTEXT_PC (CONTEXT_STATE.CONTEXT_REG(srr0))
  #define CONTEXT_EXCEPTION_POINTER (CONTEXT_STATE.CONTEXT_REG(r29))
  #define CONTEXT_YOUNG_LIMIT (CONTEXT_STATE.CONTEXT_REG(r30))
  #define CONTEXT_YOUNG_PTR (CONTEXT_STATE.CONTEXT_REG(r31))
  #define CONTEXT_SP (CONTEXT_STATE.CONTEXT_REG(r1))
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** PowerPC 32 bits, ELF (Linux) */

#elif defined(TARGET_power) && defined(MODEL_ppc) && defined(SYS_elf)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, struct sigcontext * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_handler = (void (*)(int)) (name); \
     sigact.sa_flags = 0

  typedef unsigned long context_reg;
  #define CONTEXT_PC (context->regs->nip)
  #define CONTEXT_EXCEPTION_POINTER (context->regs->gpr[29])
  #define CONTEXT_YOUNG_LIMIT (context->regs->gpr[30])
  #define CONTEXT_YOUNG_PTR (context->regs->gpr[31])
  #define CONTEXT_SP (context->regs->gpr[1])

/****************** PowerPC 64 bits, ELF (Linux) */

#elif defined(TARGET_power) && defined(SYS_elf)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
     sigact.sa_flags = SA_SIGINFO

  typedef unsigned long context_reg;
  #define CONTEXT_PC (context->uc_mcontext.gp_regs[32])
  #define CONTEXT_EXCEPTION_POINTER (context->uc_mcontext.gp_regs[29])
  #define CONTEXT_YOUNG_LIMIT (context->uc_mcontext.gp_regs[30])
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.gp_regs[31])
  #define CONTEXT_SP (context->uc_mcontext.gp_regs[1])
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/****************** PowerPC, NetBSD */

#elif defined(TARGET_power) && defined (SYS_netbsd)

  #include <ucontext.h>
  #define DECLARE_SIGNAL_HANDLER(name) \
  static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
  sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
  sigact.sa_flags = SA_SIGINFO

  typedef long context_reg;
  #define CONTEXT_PC (_UC_MACHINE_PC(context))
  #define CONTEXT_EXCEPTION_POINTER (context->uc_mcontext.__gregs[_REG_R29])
  #define CONTEXT_YOUNG_LIMIT (context->uc_mcontext.__gregs[_REG_R30])
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.__gregs[_REG_R31])
  #define CONTEXT_SP (_UC_MACHINE_SP(context))
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)


/****************** PowerPC, other BSDs */

#elif defined(TARGET_power) && \
    (defined(SYS_bsd) || defined(SYS_bsd_elf))

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, int code, struct sigcontext * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_handler = (void (*)(int)) (name); \
     sigact.sa_flags = 0

  typedef unsigned long context_reg;
  #define CONTEXT_PC (context->sc_frame.srr0)
  #define CONTEXT_EXCEPTION_POINTER (context->sc_frame.fixreg[29])
  #define CONTEXT_YOUNG_LIMIT (context->sc_frame.fixreg[30])
  #define CONTEXT_YOUNG_PTR (context->sc_frame.fixreg[31])
  #define CONTEXT_SP (context->sc_frame.fixreg[1])

/****************** s390x, ELF (Linux) */
#elif defined(TARGET_s390x) && defined(SYS_elf)

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig, siginfo_t * info, ucontext_t * context)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_sigaction = (void (*)(int,siginfo_t *,void *)) (name); \
     sigact.sa_flags = SA_SIGINFO

  typedef unsigned long context_reg;
  #define CONTEXT_PC (context->uc_mcontext.psw.addr)
  #define CONTEXT_EXCEPTION_POINTER (context->uc_mcontext.gregs[13])
  #define CONTEXT_YOUNG_LIMIT (context->uc_mcontext.gregs[10])
  #define CONTEXT_YOUNG_PTR (context->uc_mcontext.gregs[11])
  #define CONTEXT_SP (context->uc_mcontext.gregs[15])
  #define CONTEXT_FAULTING_ADDRESS ((char *) info->si_addr)

/******************** Default */

#else

  #define DECLARE_SIGNAL_HANDLER(name) \
    static void name(int sig)

  #define SET_SIGACT(sigact,name) \
     sigact.sa_handler = (name); \
     sigact.sa_flags = 0

#endif
