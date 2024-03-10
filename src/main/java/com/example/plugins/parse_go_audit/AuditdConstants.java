package com.example.plugins.parse_go_audit;

import java.util.HashMap;
import java.util.Map;

public class AuditdConstants {
    public static final Map<String, Integer> TYPES = new HashMap<>();
    public static final Map<String, Integer> ARCH = new HashMap<>();
    public static final Map<Integer, String> MACHINES = new HashMap<>();
    public static final Map<String, Map<String, String>> SYSCALLS = new HashMap<>();
    public static final Map<Integer, String> ADDRESS_FAMILIES = new HashMap<>();

    static {
        TYPES.put("syscall", 1300);        // Syscall event
        TYPES.put("path", 1302);           // Filename path information
        TYPES.put("ipc", 1303);            // IPC record
        TYPES.put("socketcall", 1304);     // sys_socketcall arguments
        TYPES.put("config_change", 1305);  // Audit system configuration change
        TYPES.put("sockaddr", 1306);       // sockaddr copied as syscall arg
        TYPES.put("cwd", 1307);            // Current working directory
        TYPES.put("execve", 1309);         // execve arguments
        TYPES.put("ipc_set_perm", 1311);   // IPC new permissions record type
        TYPES.put("mq_open", 1312);        // POSIX MQ open record type
        TYPES.put("mq_sendrecv", 1313);    // POSIX MQ send/receive record type
        TYPES.put("mq_notify", 1314);      // POSIX MQ notify record type
        TYPES.put("mq_getsetattr", 1315);  // POSIX MQ get/set attribute record type
        TYPES.put("kernel_other", 1316);   // For use by 3rd party modules
        TYPES.put("fd_pair", 1317);        // audit record for pipe/socketpair
        TYPES.put("obj_pid", 1318);        // ptrace target
        TYPES.put("tty", 1319);            // Input on an administrative TTY
        TYPES.put("eoe", 1320);            // End of multi-record event
        TYPES.put("bprm_fcaps", 1321);     // Information about fcaps increasing perms
        TYPES.put("capset", 1322);         // Record showing argument to sys_capset
        TYPES.put("mmap", 1323);           // Record showing descriptor and flags in mmap
        TYPES.put("netfilter_pkt", 1324);  // Packets traversing netfilter chains
        TYPES.put("netfilter_cfg", 1325);  // Netfilter chain modifications
        TYPES.put("seccomp", 1326);        // Secure Computing event
        TYPES.put("proctitle", 1327);      // Proctitle emit event
        TYPES.put("feature_change", 1328); // audit log listing feature changes
        TYPES.put("replace", 1329);        // Replace auditd if this packet unanswerd
 
        ARCH.put("64bit", 0x80000000);
        ARCH.put("little_endian", 0x40000000);
        ARCH.put("convention_mips64_n32", 0x20000000);

        MACHINES.put(0, "none");         // Unknown machine.
        MACHINES.put(1, "m32");          // AT&T WE32100.
        MACHINES.put(2, "sparc");        // Sun SPARC.
        MACHINES.put(3, "386");          // Intel i386.
        MACHINES.put(4, "68k");          // Motorola 68000.
        MACHINES.put(5, "88k");          // Motorola 88000.
        MACHINES.put(7, "860");          // Intel i860.
        MACHINES.put(8, "mips");         // MIPS R3000 Big-Endian only.
        MACHINES.put(9, "s370");         // IBM System/370.
        MACHINES.put(10, "mips_rs3_le"); // MIPS R3000 Little-Endian.
        MACHINES.put(15, "parisc");      // HP PA-RISC.
        MACHINES.put(17, "vpp500");      // Fujitsu VPP500.
        MACHINES.put(18, "sparc32plus"); // SPARC v8plus.
        MACHINES.put(19, "960");         // Intel 80960.
        MACHINES.put(20, "ppc");         // PowerPC 32-bit.
        MACHINES.put(21, "ppc64");       // PowerPC 64-bit.
        MACHINES.put(22, "s390");        // IBM System/390.
        MACHINES.put(36, "v800");        // NEC V800.
        MACHINES.put(37, "fr20");        // Fujitsu FR20.
        MACHINES.put(38, "rh32");        // TRW RH-32.
        MACHINES.put(39, "rce");         // Motorola RCE.
        MACHINES.put(40, "arm");         // ARM.
        MACHINES.put(42, "sh");          // Hitachi SH.
        MACHINES.put(43, "sparcv9");     // SPARC v9 64-bit.
        MACHINES.put(44, "tricore");     // Siemens TriCore embedded processor.
        MACHINES.put(45, "arc");         // Argonaut RISC Core.
        MACHINES.put(46, "h8_300");      // Hitachi H8/300.
        MACHINES.put(47, "h8_300h");     // Hitachi H8/300H.
        MACHINES.put(48, "h8s");         // Hitachi H8S.
        MACHINES.put(49, "h8_500");      // Hitachi H8/500.
        MACHINES.put(50, "ia_64");       // Intel IA-64 Processor.
        MACHINES.put(51, "mips_x");      // Stanford MIPS-X.
        MACHINES.put(52, "coldfire");    // Motorola ColdFire.
        MACHINES.put(53, "68hc12");      // Motorola M68HC12.
        MACHINES.put(54, "mma");         // Fujitsu MMA.
        MACHINES.put(55, "pcp");         // Siemens PCP.
        MACHINES.put(56, "ncpu");        // Sony nCPU.
        MACHINES.put(57, "ndr1");        // Denso NDR1 microprocessor.
        MACHINES.put(58, "starcore");    // Motorola Star*Core processor.
        MACHINES.put(59, "me16");        // Toyota ME16 processor.
        MACHINES.put(60, "st100");       // STMicroelectronics ST100 processor.
        MACHINES.put(61, "tinyj");       // Advanced Logic Corp. TinyJ processor.
        MACHINES.put(62, "x86_64");      // Advanced Micro Devices x86-64
        MACHINES.put(183, "aarch64");    // ARM 64-bit Architecture (AArch64)

        Map<String, String> x86_64Syscalls = new HashMap<>();

        x86_64Syscalls.put("0", "read");
        x86_64Syscalls.put("1", "write");
        x86_64Syscalls.put("2", "open");
        x86_64Syscalls.put("3", "close");
        x86_64Syscalls.put("4", "stat");
        x86_64Syscalls.put("5", "fstat");
        x86_64Syscalls.put("6", "lstat");
        x86_64Syscalls.put("7", "poll");
        x86_64Syscalls.put("8", "lseek");
        x86_64Syscalls.put("9", "mmap");
        x86_64Syscalls.put("10", "mprotect");
        x86_64Syscalls.put("11", "munmap");
        x86_64Syscalls.put("12", "brk");
        x86_64Syscalls.put("13", "rt_sigaction");
        x86_64Syscalls.put("14", "rt_sigprocmask");
        x86_64Syscalls.put("15", "rt_sigreturn");
        x86_64Syscalls.put("16", "ioctl");
        x86_64Syscalls.put("17", "pread64");
        x86_64Syscalls.put("18", "pwrite64");
        x86_64Syscalls.put("19", "readv");
        x86_64Syscalls.put("20", "writev");
        x86_64Syscalls.put("21", "access");
        x86_64Syscalls.put("22", "pipe");
        x86_64Syscalls.put("23", "select");
        x86_64Syscalls.put("24", "sched_yield");
        x86_64Syscalls.put("25", "mremap");
        x86_64Syscalls.put("26", "msync");
        x86_64Syscalls.put("27", "mincore");
        x86_64Syscalls.put("28", "madvise");
        x86_64Syscalls.put("29", "shmget");
        x86_64Syscalls.put("30", "shmat");
        x86_64Syscalls.put("31", "shmctl");
        x86_64Syscalls.put("32", "dup");
        x86_64Syscalls.put("33", "dup2");
        x86_64Syscalls.put("34", "pause");
        x86_64Syscalls.put("35", "nanosleep");
        x86_64Syscalls.put("36", "getitimer");
        x86_64Syscalls.put("37", "alarm");
        x86_64Syscalls.put("38", "setitimer");
        x86_64Syscalls.put("39", "getpid");
        x86_64Syscalls.put("40", "sendfile");
        x86_64Syscalls.put("41", "socket");
        x86_64Syscalls.put("42", "connect");
        x86_64Syscalls.put("43", "accept");
        x86_64Syscalls.put("44", "sendto");
        x86_64Syscalls.put("45", "recvfrom");
        x86_64Syscalls.put("46", "sendmsg");
        x86_64Syscalls.put("47", "recvmsg");
        x86_64Syscalls.put("48", "shutdown");
        x86_64Syscalls.put("49", "bind");
        x86_64Syscalls.put("50", "listen");
        x86_64Syscalls.put("51", "getsockname");
        x86_64Syscalls.put("52", "getpeername");
        x86_64Syscalls.put("53", "socketpair");
        x86_64Syscalls.put("54", "setsockopt");
        x86_64Syscalls.put("55", "getsockopt");
        x86_64Syscalls.put("56", "clone");
        x86_64Syscalls.put("57", "fork");
        x86_64Syscalls.put("58", "vfork");
        x86_64Syscalls.put("59", "execve");
        x86_64Syscalls.put("60", "exit");
        x86_64Syscalls.put("61", "wait4");
        x86_64Syscalls.put("62", "kill");
        x86_64Syscalls.put("63", "uname");
        x86_64Syscalls.put("64", "semget");
        x86_64Syscalls.put("65", "semop");
        x86_64Syscalls.put("66", "semctl");
        x86_64Syscalls.put("67", "shmdt");
        x86_64Syscalls.put("68", "msgget");
        x86_64Syscalls.put("69", "msgsnd");
        x86_64Syscalls.put("70", "msgrcv");
        x86_64Syscalls.put("71", "msgctl");
        x86_64Syscalls.put("72", "fcntl");
        x86_64Syscalls.put("73", "flock");
        x86_64Syscalls.put("74", "fsync");
        x86_64Syscalls.put("75", "fdatasync");
        x86_64Syscalls.put("76", "truncate");
        x86_64Syscalls.put("77", "ftruncate");
        x86_64Syscalls.put("78", "getdents");
        x86_64Syscalls.put("79", "getcwd");
        x86_64Syscalls.put("80", "chdir");
        x86_64Syscalls.put("81", "fchdir");
        x86_64Syscalls.put("82", "rename");
        x86_64Syscalls.put("83", "mkdir");
        x86_64Syscalls.put("84", "rmdir");
        x86_64Syscalls.put("85", "creat");
        x86_64Syscalls.put("86", "link");
        x86_64Syscalls.put("87", "unlink");
        x86_64Syscalls.put("88", "symlink");
        x86_64Syscalls.put("89", "readlink");
        x86_64Syscalls.put("90", "chmod");
        x86_64Syscalls.put("91", "fchmod");
        x86_64Syscalls.put("92", "chown");
        x86_64Syscalls.put("93", "fchown");
        x86_64Syscalls.put("94", "lchown");
        x86_64Syscalls.put("95", "umask");
        x86_64Syscalls.put("96", "gettimeofday");
        x86_64Syscalls.put("97", "getrlimit");
        x86_64Syscalls.put("98", "getrusage");
        x86_64Syscalls.put("99", "sysinfo");
        x86_64Syscalls.put("100", "times");
        x86_64Syscalls.put("101", "ptrace");
        x86_64Syscalls.put("102", "getuid");
        x86_64Syscalls.put("103", "syslog");
        x86_64Syscalls.put("104", "getgid");
        x86_64Syscalls.put("105", "setuid");
        x86_64Syscalls.put("106", "setgid");
        x86_64Syscalls.put("107", "geteuid");
        x86_64Syscalls.put("108", "getegid");
        x86_64Syscalls.put("109", "setpgid");
        x86_64Syscalls.put("110", "getppid");
        x86_64Syscalls.put("111", "getpgrp");
        x86_64Syscalls.put("112", "setsid");
        x86_64Syscalls.put("113", "setreuid");
        x86_64Syscalls.put("114", "setregid");
        x86_64Syscalls.put("115", "getgroups");
        x86_64Syscalls.put("116", "setgroups");
        x86_64Syscalls.put("117", "setresuid");
        x86_64Syscalls.put("118", "getresuid");
        x86_64Syscalls.put("119", "setresgid");
        x86_64Syscalls.put("120", "getresgid");
        x86_64Syscalls.put("121", "getpgid");
        x86_64Syscalls.put("122", "setfsuid");
        x86_64Syscalls.put("123", "setfsgid");
        x86_64Syscalls.put("124", "getsid");
        x86_64Syscalls.put("125", "capget");
        x86_64Syscalls.put("126", "capset");
        x86_64Syscalls.put("127", "rt_sigpending");
        x86_64Syscalls.put("128", "rt_sigtimedwait");
        x86_64Syscalls.put("129", "rt_sigqueueinfo");
        x86_64Syscalls.put("130", "rt_sigsuspend");
        x86_64Syscalls.put("131", "sigaltstack");
        x86_64Syscalls.put("132", "utime");
        x86_64Syscalls.put("133", "mknod");
        x86_64Syscalls.put("134", "uselib");
        x86_64Syscalls.put("135", "personality");
        x86_64Syscalls.put("136", "ustat");
        x86_64Syscalls.put("137", "statfs");
        x86_64Syscalls.put("138", "fstatfs");
        x86_64Syscalls.put("139", "sysfs");
        x86_64Syscalls.put("140", "getpriority");
        x86_64Syscalls.put("141", "setpriority");
        x86_64Syscalls.put("142", "sched_setparam");
        x86_64Syscalls.put("143", "sched_getparam");
        x86_64Syscalls.put("144", "sched_setscheduler");
        x86_64Syscalls.put("145", "sched_getscheduler");
        x86_64Syscalls.put("146", "sched_get_priority_max");
        x86_64Syscalls.put("147", "sched_get_priority_min");
        x86_64Syscalls.put("148", "sched_rr_get_interval");
        x86_64Syscalls.put("149", "mlock");
        x86_64Syscalls.put("150", "munlock");
        x86_64Syscalls.put("151", "mlockall");
        x86_64Syscalls.put("152", "munlockall");
        x86_64Syscalls.put("153", "vhangup");
        x86_64Syscalls.put("154", "modify_ldt");
        x86_64Syscalls.put("155", "pivot_root");
        x86_64Syscalls.put("156", "_sysctl");
        x86_64Syscalls.put("157", "prctl");
        x86_64Syscalls.put("158", "arch_prctl");
        x86_64Syscalls.put("159", "adjtimex");
        x86_64Syscalls.put("160", "setrlimit");
        x86_64Syscalls.put("161", "chroot");
        x86_64Syscalls.put("162", "sync");
        x86_64Syscalls.put("163", "acct");
        x86_64Syscalls.put("164", "settimeofday");
        x86_64Syscalls.put("165", "mount");
        x86_64Syscalls.put("166", "umount2");
        x86_64Syscalls.put("167", "swapon");
        x86_64Syscalls.put("168", "swapoff");
        x86_64Syscalls.put("169", "reboot");
        x86_64Syscalls.put("170", "sethostname");
        x86_64Syscalls.put("171", "setdomainname");
        x86_64Syscalls.put("172", "iopl");
        x86_64Syscalls.put("173", "ioperm");
        x86_64Syscalls.put("174", "create_module");
        x86_64Syscalls.put("175", "init_module");
        x86_64Syscalls.put("176", "delete_module");
        x86_64Syscalls.put("177", "get_kernel_syms");
        x86_64Syscalls.put("178", "query_module");
        x86_64Syscalls.put("179", "quotactl");
        x86_64Syscalls.put("180", "nfsservctl");
        x86_64Syscalls.put("181", "getpmsg");
        x86_64Syscalls.put("182", "putpmsg");
        x86_64Syscalls.put("183", "afs_syscall");
        x86_64Syscalls.put("184", "tuxcall");
        x86_64Syscalls.put("185", "security");
        x86_64Syscalls.put("186", "gettid");
        x86_64Syscalls.put("187", "readahead");
        x86_64Syscalls.put("188", "setxattr");
        x86_64Syscalls.put("189", "lsetxattr");
        x86_64Syscalls.put("190", "fsetxattr");
        x86_64Syscalls.put("191", "getxattr");
        x86_64Syscalls.put("192", "lgetxattr");
        x86_64Syscalls.put("193", "fgetxattr");
        x86_64Syscalls.put("194", "listxattr");
        x86_64Syscalls.put("195", "llistxattr");
        x86_64Syscalls.put("196", "flistxattr");
        x86_64Syscalls.put("197", "removexattr");
        x86_64Syscalls.put("198", "lremovexattr");
        x86_64Syscalls.put("199", "fremovexattr");
        x86_64Syscalls.put("200", "tkill");
        x86_64Syscalls.put("201", "time");
        x86_64Syscalls.put("202", "futex");
        x86_64Syscalls.put("203", "sched_setaffinity");
        x86_64Syscalls.put("204", "sched_getaffinity");
        x86_64Syscalls.put("205", "set_thread_area");
        x86_64Syscalls.put("206", "io_setup");
        x86_64Syscalls.put("207", "io_destroy");
        x86_64Syscalls.put("208", "io_getevents");
        x86_64Syscalls.put("209", "io_submit");
        x86_64Syscalls.put("210", "io_cancel");
        x86_64Syscalls.put("211", "get_thread_area");
        x86_64Syscalls.put("212", "lookup_dcookie");
        x86_64Syscalls.put("213", "epoll_create");
        x86_64Syscalls.put("214", "epoll_ctl_old");
        x86_64Syscalls.put("215", "epoll_wait_old");
        x86_64Syscalls.put("216", "remap_file_pages");
        x86_64Syscalls.put("217", "getdents64");
        x86_64Syscalls.put("218", "set_tid_address");
        x86_64Syscalls.put("219", "restart_syscall");
        x86_64Syscalls.put("220", "settimedop");
        x86_64Syscalls.put("221", "fadvise64");
        x86_64Syscalls.put("222", "timer_create");
        x86_64Syscalls.put("223", "timer_settime");
        x86_64Syscalls.put("224", "timer_gettime");
        x86_64Syscalls.put("225", "timer_getoverrun");
        x86_64Syscalls.put("226", "timer_delete");
        x86_64Syscalls.put("227", "clock_settime");
        x86_64Syscalls.put("228", "clock_gettime");
        x86_64Syscalls.put("229", "clock_getres");
        x86_64Syscalls.put("230", "clock_nanosleep");
        x86_64Syscalls.put("231", "exit_group");
        x86_64Syscalls.put("232", "epoll_wait");
        x86_64Syscalls.put("233", "epoll_ctl");
        x86_64Syscalls.put("234", "tgkill");
        x86_64Syscalls.put("235", "utimes");
        x86_64Syscalls.put("236", "vserver");
        x86_64Syscalls.put("237", "mbind");
        x86_64Syscalls.put("238", "set_mempolicy");
        x86_64Syscalls.put("239", "get_mempolicy");
        x86_64Syscalls.put("240", "mq_open");
        x86_64Syscalls.put("241", "mq_unlink");
        x86_64Syscalls.put("242", "mq_timedsend");
        x86_64Syscalls.put("243", "mq_timedreceive");
        x86_64Syscalls.put("244", "mq_notify");
        x86_64Syscalls.put("245", "mq_getsetattr");
        x86_64Syscalls.put("246", "kexec_load");
        x86_64Syscalls.put("247", "waitid");
        x86_64Syscalls.put("248", "add_key");
        x86_64Syscalls.put("249", "request_key");
        x86_64Syscalls.put("250", "keyctl");
        x86_64Syscalls.put("251", "ioprio_set");
        x86_64Syscalls.put("252", "ioprio_get");
        x86_64Syscalls.put("253", "inotify_init");
        x86_64Syscalls.put("254", "inotify_add_watch");
        x86_64Syscalls.put("255", "inotify_rm_watch");
        x86_64Syscalls.put("256", "migrate_pages");
        x86_64Syscalls.put("257", "openat");
        x86_64Syscalls.put("258", "mkdirat");
        x86_64Syscalls.put("259", "mknodat");
        x86_64Syscalls.put("260", "fchownat");
        x86_64Syscalls.put("261", "futimesat");
        x86_64Syscalls.put("262", "newfstatat");
        x86_64Syscalls.put("263", "unlinkat");
        x86_64Syscalls.put("264", "renameat");
        x86_64Syscalls.put("265", "linkat");
        x86_64Syscalls.put("266", "symlinkat");
        x86_64Syscalls.put("267", "readlinkat");
        x86_64Syscalls.put("268", "fchmodat");
        x86_64Syscalls.put("269", "faccessat");
        x86_64Syscalls.put("270", "pselect6");
        x86_64Syscalls.put("271", "ppoll");
        x86_64Syscalls.put("272", "unshare");
        x86_64Syscalls.put("273", "set_robust_list");
        x86_64Syscalls.put("274", "get_robust_list");
        x86_64Syscalls.put("275", "splice");
        x86_64Syscalls.put("276", "tee");
        x86_64Syscalls.put("277", "sync_file_range");
        x86_64Syscalls.put("278", "vmsplice");
        x86_64Syscalls.put("279", "move_pages");
        x86_64Syscalls.put("280", "utimensat");
        x86_64Syscalls.put("281", "epoll_pwait");
        x86_64Syscalls.put("282", "signalfd");
        x86_64Syscalls.put("283", "timerfd_create");
        x86_64Syscalls.put("284", "eventfd");
        x86_64Syscalls.put("285", "fallocate");
        x86_64Syscalls.put("286", "timerfd_settime");
        x86_64Syscalls.put("287", "timerfd_gettime");
        x86_64Syscalls.put("288", "accept4");
        x86_64Syscalls.put("289", "signalfd4");
        x86_64Syscalls.put("290", "eventfd2");
        x86_64Syscalls.put("291", "epoll_create1");
        x86_64Syscalls.put("292", "dup3");
        x86_64Syscalls.put("293", "pipe2");
        x86_64Syscalls.put("294", "inotify_init1");
        x86_64Syscalls.put("295", "preadv");
        x86_64Syscalls.put("296", "pwritev");
        x86_64Syscalls.put("297", "rt_tgsigqueueinfo");
        x86_64Syscalls.put("298", "perf_event_open");
        x86_64Syscalls.put("299", "recvmmsg");
        x86_64Syscalls.put("300", "fanotify_init");
        x86_64Syscalls.put("301", "fanotify_mark");
        x86_64Syscalls.put("302", "prlimit64");
        x86_64Syscalls.put("303", "name_to_handle_at");
        x86_64Syscalls.put("304", "open_by_handle_at");
        x86_64Syscalls.put("305", "clock_adjtime");
        x86_64Syscalls.put("306", "syncfs");
        x86_64Syscalls.put("307", "sendmmsg");
        x86_64Syscalls.put("308", "setns");
        x86_64Syscalls.put("309", "getcpu");
        x86_64Syscalls.put("310", "process_vm_readv");
        x86_64Syscalls.put("311", "process_vm_writev");
        x86_64Syscalls.put("312", "kcmp");
        x86_64Syscalls.put("313", "finit_module");

        SYSCALLS.put("x86_64", x86_64Syscalls);

        ADDRESS_FAMILIES.put(0, "unspecified");
        ADDRESS_FAMILIES.put(1, "local");
        ADDRESS_FAMILIES.put(2, "inet");
        ADDRESS_FAMILIES.put(3, "ax25");
        ADDRESS_FAMILIES.put(4, "ipx");
        ADDRESS_FAMILIES.put(5, "appletalk");
        ADDRESS_FAMILIES.put(6, "netrom");
        ADDRESS_FAMILIES.put(7, "bridge");
        ADDRESS_FAMILIES.put(8, "atmpvc");
        ADDRESS_FAMILIES.put(9, "x25");
        ADDRESS_FAMILIES.put(10, "inet6");
        ADDRESS_FAMILIES.put(11, "rose");
        ADDRESS_FAMILIES.put(12, "decnet");
        ADDRESS_FAMILIES.put(13, "netbeui");
        ADDRESS_FAMILIES.put(14, "security");
        ADDRESS_FAMILIES.put(15, "key");
        ADDRESS_FAMILIES.put(16, "netlink");
        ADDRESS_FAMILIES.put(17, "packet");
        ADDRESS_FAMILIES.put(18, "ash");
        ADDRESS_FAMILIES.put(19, "econet");
        ADDRESS_FAMILIES.put(20, "atmsvc");
        ADDRESS_FAMILIES.put(21, "rds");
        ADDRESS_FAMILIES.put(22, "sna");
        ADDRESS_FAMILIES.put(23, "irda");
        ADDRESS_FAMILIES.put(24, "pppox");
        ADDRESS_FAMILIES.put(25, "wanpipe");
        ADDRESS_FAMILIES.put(26, "llc");
        ADDRESS_FAMILIES.put(27, "ib");
        ADDRESS_FAMILIES.put(28, "mpls");
        ADDRESS_FAMILIES.put(29, "can");
        ADDRESS_FAMILIES.put(30, "tipc");
        ADDRESS_FAMILIES.put(31, "bluetooth");
        ADDRESS_FAMILIES.put(32, "iucv");
        ADDRESS_FAMILIES.put(33, "rxrpc");
        ADDRESS_FAMILIES.put(34, "isdn");
        ADDRESS_FAMILIES.put(35, "phonet");
        ADDRESS_FAMILIES.put(36, "ieee802154");
        ADDRESS_FAMILIES.put(37, "caif");
        ADDRESS_FAMILIES.put(38, "alg");
        ADDRESS_FAMILIES.put(39, "nfc");
        ADDRESS_FAMILIES.put(40, "vsock");
        ADDRESS_FAMILIES.put(41, "kcm");
        ADDRESS_FAMILIES.put(42, "qipcrtr");
    }
}