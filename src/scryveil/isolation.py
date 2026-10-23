"""Fail-closed Linux worker syscall policy; no untrusted code loading.

libseccomp resolves native syscall numbers and enforces architecture checks.
Workers receive pipes only; filesystem opens, process creation, ptrace and new
network connections are denied. This is not protection against a hostile kernel.
"""

import ctypes
import errno
import os
import resource
import sys

from .models import ScryveilError


def restrict_worker(connected_socket: bool = False) -> None:
    if sys.platform != "linux":
        raise ScryveilError("isolation_unavailable", 4)
    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        libc.prctl.restype = ctypes.c_int
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_rule_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        lib.seccomp_rule_add.restype = ctypes.c_int
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_release.argtypes = [ctypes.c_void_p]
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        os.environ.clear()
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise OSError
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            raise OSError
        ctx = lib.seccomp_init(0x00050000 | errno.EPERM)
        if not ctx:
            raise OSError
        allowed = "read write close fstat lseek brk mmap mprotect munmap mremap madvise futex clock_gettime gettimeofday rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack getpid gettid exit exit_group getrandom poll ppoll select pselect6 restart_syscall"
        if connected_socket:
            # Only a previously connected, destination-validated socket exists.
            allowed += " recvfrom sendto recvmsg sendmsg shutdown getsockopt setsockopt ioctl"
        try:
            for name in allowed.split():
                number = lib.seccomp_syscall_resolve_name(name.encode())
                if number >= 0 and lib.seccomp_rule_add(ctx, 0x7FFF0000, number, 0) != 0:
                    raise OSError
            if lib.seccomp_load(ctx) != 0:
                raise OSError
        finally:
            lib.seccomp_release(ctx)
    except (OSError, AttributeError, ValueError) as exc:
        raise ScryveilError("isolation_unavailable", 4) from exc
