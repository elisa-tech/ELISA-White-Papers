## Discovering Linux kernel subsystems used by a workload
#### Authors: 
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**Shuah Khan <<skhan@linuxfoundation.org>> <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Shefali Sharma <<sshefali021@gmail.com>>**

#### Key Points
- Understanding system resources necessary to build and run a workload is important.
- Linux tracing and strace can be used to discover the system resources in use by a workload. The completeness of the system usage information depends on the completeness of coverage of a workload.
- Performance and security of the operating system can be analyzed with the help of tools like perf, stress-ng, paxtest.
- Once we discover and understand the workload needs, we can focus on them to avoid regressions and use it to evaluate safety considerations.

In our previous blog [Discovery Linux Kernel Subsystems used by OpenAPS](https://elisa.tech/blog/2022/02/02/discovery-linux-kernel-subsystems-used-by-openaps/), we gathered a higher level of information about the OpenAPS usage. It isn’t ideal that this higher information doesn’t tell us the system usage by individual OpenAPS commands. As an example, we won’t be able to clearly identify which system calls are invoked when a user queries insulin pump status.

Continuing on our work, we identified a process for gathering fine grained information about system resources necessary to run a workload on Linux. This process can then be applied to any workload including individual OpenAPS commands and important use-cases. As an example, what subsystems are used when a user queries the insulin pump status. 

We chose an easily available [strace](https://man7.org/linux/man-pages/man1/strace.1.html) which is a useful diagnostic, instructional, and debugging tool and can be used to discover the system resources in use by a workload. Once we discover and understand the workload needs, we can focus on them to avoid regressions and use it to evaluate safety considerations.

This method of tracing tells us the system calls invoked by the workload and doesn't include all the system calls that can be invoked. In addition to that this trace tells us just the code paths within these system calls that are invoked. As an example, if a workload opens a file and reads from it successfully, then the success path is the one that is traced. Any error paths in that system call will not be traced. If there is a workload that provides full coverage the method outlined here will trace and find all possible code paths. The completeness of the system usage information depends on the completeness of coverage of a workload.

#### How did we gather fine grained system information?

We used the strace command to trace the perf,  stress-ng, paxtest workloads. System calls are the fundamental interface between an application and the operating system kernel. They enable a program to request services from the kernel. For instance, the open() system call in Linux is used to provide access to a file in the file system. **strace** enables us to track all the system calls made by an application. It lists all the system calls made by a process with the outputs of those calls.

#### Get the system ready for tracing

Before we can get started we will have to get our system ready. We assume that you have a Linux distro running on a physical system or virtual machine. Most distributions will include **strace command**. Let’s install other tools that aren’t usually included to build Linux kernel. Please note that the following works on Debian based distributions. You might have to find equivalent packages on other Linux distributions.

- **Install tools to build Linux kernel and tools in kernel repo.**
  - `sudo apt-get build-essentials flex bison yacc`
  - `sudo apt install libelf-dev systemtap-sdt-dev libaudit-dev libslang2-dev libperl-dev libdw-dev`
- **Browsing kernel sources**
  - `sudo apt-get install cscope`
- **Install stress-ng**
  - `apt-get install stress-ng`
- **Install paxtest**
  - `apt-get install paxtest`

We plan to use strace to trace perf bench, stress-ng and paxtest workloads to show you how to analyze a workload and identify Linux subsystems used by these workloads. We hope you will be able to apply this process to trace your workload(s).

- **perf bench (all) workload:**
  - The perf bench command contains multiple multithreaded microkernel benchmarks for executing different subsystems in the Linux kernel and system calls. This allows us to easily measure the impact of changes, which can help mitigate performance regressions. It also acts as a common benchmarking framework, enabling developers to easily create test cases, integrate transparently, and use performance-rich tooling subsystems.
- **Stress-ng netdev stressor workload:**
  - stress-ng is used for performing stress testing on the kernel. It allows you to exercise various physical subsystems of the computer, as well as interfaces of the OS kernel, using "stressors". They are available for CPU, CPU cache, devices, I/O, interrupts, file system, memory, network, operating system, pipelines, schedulers, virtual machines. You may find the description of all the available stressors here. The netdev stressor starts N  workers  that  exercise  various  netdevice ioctl commands across all the available network devices.
- **paxtest kiddie workload:**
  - paxtest is a program that tests buffer overflows in the kernel. It tests kernel enforcements over memory usage. Generally, execution in some memory segments makes buffer overflows possible. It runs a set of programs that attempt to subvert memory usage. It is used as a regression test suite for PaX, but might be useful to test other memory protection patches for the kernel. We plan to use paxtest kiddie mode which looks for simple vulnerabilities.

#### What is strace and how do we use it?
As mentioned earlier, strace which is a useful diagnostic, instructional, and debugging tool and can be used to discover the system resources in use by a workload. It can be used:
- To see how a process interacts with the kernel.
- To see why a process is failing or hanging.
- For reverse engineering a process.
- To find the files on which a program depends.
- For analyzing the performance of an application.
- For troubleshooting various problems related to the operating system.

In addition, strace can generate run-time statistics on time, calls, and errors for each system call and  report  a  summary  on  program exit, suppressing the regular output.  This attempts to show system time (CPU time  spent running  in the kernel) independent of wall clock time. We plan to use these features to get information on workload system usage. Let’s get started with a few **strace** example runs of basic, verbose, and stats modes. We are going to use the “-c” option for gathering fine grained information. Let’s first look at a few examples on how to use “strace”.

##### Usage: `strace <command we want to trace>`
The following image shows `strace ls` output which shows system usage by “ls” command as it uses Linux System Calls to find and list information about the FILEs that reside under a directory.

![strace ls output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/strace-ls.png)

##### Verbose mode usage: `strace -v <command>`
strace command when run in verbose mode gives more detailed information about the system calls. The following image shows `strace -v ifconfig` output.

![strace -v ifconfig output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/strace-ifconfig.png)

##### Gather statistics
We can use the -c parameter to generate a report of the percentage of time spent in each system call, the total time in seconds, the microseconds per call, the total number of calls, the count of each system call that has failed with an error and the type of system call made - `strace -c <command>`. The following image shows `strace -c date` output that includes a summary of system usage statistics for “date” command.

![strace -c date output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/strace-date.png)

#### What is cscope and how do we use it?
Now let’s look at **cscope**, a command line tool for browsing C, C++ or Java codebases. We can use it to find all the references to a symbol, global definitions, functions called by a function, functions calling a function, text strings, regular expression patterns, files including a file.

We can use cscope to find which system call belongs to which subsystem. This way we can find the kernel subsystems used by a process when it is executed. To use it navigate to the source code directory. Here we are analyzing the kernel source tree.

First let’s checkout the latest Linux repository and build cscope database:
- `git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux`
- `cd linux`
- `cscope -R -p10` or `cscope -d -p10`
  
Note: Run **cscope -R** to build the database (run it only once) and **cscope -d -p10** to enter into the interactive mode of cscope. To get out of this mode press **ctrl+d**.

![cscope -R output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/cscope-R.png)

All the system calls are defined in the kernel using the SYSCALL_DEFINE[0-6] macro in their respective subsystem directory. We can search for this egrep pattern to find all the system calls and their subsystems (Press the Tab key to go back to the cscope options). 

![system call subsystem info](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/egrep-pattern.png)

#### Perf

Perf is an analysis tool based on Linux 2.6+ systems, which abstracts the CPU hardware difference in performance measurement in Linux, and provides a simple command line interface. Perf is based on the perf_events interface exported by the kernel. It is very useful for profiling the system and finding performance bottlenecks in an application.

If you haven't already checkout the Linux mainline repository, you can do so and then build kernel and perf tool:
- `git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux`
- `cd linux`
- `make -j3 all`
- `cd tools/perf`
- `make`

**Note:** The perf command can be built without building the kernel in the repo and can be run on older kernels. However matching the kernel and perf revisions gives more accurate information on the subsystem usage.
  
The following image shows the “make perf” output:

![make perf output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-make.png)

##### How to use the perf command?

Let’s look at perf tool usage and options now that we successfully built lt. The following image shows the perf command usage and options.

![./perf -h output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-h.png)

##### perf stat

The **perf stat** command generates a report of various hardware and software events. It does so with the help of hardware counter registers found in modern CPUs that keep the count of these activities. The following image shows `./perf stat` run on `cal` command.

![./perf stat cal output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-stat-cal.png)

##### Perf bench

The **perf bench** command contains multiple multithreaded microkernel benchmarks for executing different subsystems in the Linux kernel and system calls. This allows us to easily measure the impact of changes, which can help mitigate performance regressions. It also acts as a common benchmarking framework, enabling developers to easily create test cases, integrate transparently, and use performance-rich tooling subsystems. The following image shows `./perf bench all` output

![./perf bench all output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-bench-all.png)

##### Tracing perf bench all workload

Now let’s run it under strace to see which system calls it is making:
- `strace -c ./perf bench all`
  
![strace perf bench all output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/strace-perf-bench-all.png)

##### System Calls made by the workload:
The following table shows you the system calls, frequency and the Linux subsystem they fall under with links to their corresponding system call entry points with link to the Linux kernel repository.

| System Call | Frequency | Linux Subsystem | System Call Entry Point (API) |
| - | - | - | - |
| getppid | 10000001 | Process Mgmt | [sys_getpid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| clone | 1077 | Process Mgmt. | [sys_clone()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| prctl | 23 | Process Mgmt. | [sys_prctl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| prlimit64 | 7 | Process Mgmt. | [sys_prlimit64()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getpid | 10 | Process Mgmt. | [sys_getpid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| uname | 3 | Process Mgmt. | [sys_uname()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| sysinfo | 1 | Process Mgmt. | [sys_sysinfo()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getuid | 1 | Process Mgmt. | [sys_getuid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getgid | 1 | Process Mgmt. | [sys_getgid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| geteuid | 1 | Process Mgmt. | [sys_geteuid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getegid | 1 | Process Mgmt. | [sys_getegid](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getpgrp | 1 | Process Mgmt. | [sys_getpgrp()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| write | 3023462 | Filesystem | [sys_write()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| read | 1392702 | Filesystem | [sys_read()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| close | 49951 | Filesystem | [sys_close()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| pipe | 604 | Filesystem | [sys_pipe()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| openat | 48560 | Filesystem | [sys_opennat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| fstat | 8338 | Filesystem | [sys_fstat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| stat | 1573 | Filesystem | [sys_stat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| pread64 | 9646 | Filesystem | [sys_pread64()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getdents64 | 1873 | Filesystem | [sys_getdents64()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| access | 3 | Filesystem | [sys_access()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| lstat | 1880 | Filesystem | [sys_lstat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| lseek | 6 | Filesystem | [sys_lseek()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| ioctl | 3 | Filesystem | [sys_ioctl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| dup2 | 1 | Filesystem | [sys_dup2()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| execve | 2 | Filesystem | [sys_execve()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| fcntl | 8779 | Filesystem | [sys_fcntl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| statfs | 1 | Filesystem | [sys_statfs()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| epoll_create | 2 | Filesystem | [sys_epoll_create()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| epoll_ctl | 64 | Filesystem | [sys_epoll_ctl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| newfstatat | 8318 | Filesystem | [sys_newfstatat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| eventfd2 | 192 | Filesystem | [sys_eventfd2()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| mmap | 243 | Memory Mgmt. | [sys_mmap()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| mprotect | 32 | Memory Mgmt. | [sys_mprotect()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| brk | 21 | Memory Mgmt. | [sys_brk()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| munmap | 128 | Memory Mgmt. | [sys_munmap()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| set_mempolicy | 156 | Memory Mgmt. | [sys_set_mempolicy()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| set_tid_address | 1 | Process Mgmt. | [sys_set_tid_address()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| set_robust_list | 1 | Futex | [sys_set_robust_list()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| futex | 341 | Futex | [sys_futex()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| sched_getaffinity | 79 | Scheduler | [sys_sched_getaffinity()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| sched_setaffinity | 223 | Scheduler | [sys_sched_setaffinity()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| socketpair | 202 | Network | [sys_socketpair()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigprocmask | 21 | Signal | [sys_rt_sigprocmask()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigaction | 36 | Signal | [sys_rt_sigaction()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigreturn | 2 | Signal | [sys_rt_sigreturn()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| wait4 | 889 | Time | [sys_wait4()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| clock_nanosleep | 37 | Time | [sys_clock_nanosleep()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| capget | 4 | Capability | [sys_capget()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |



#### stress-ng
stress-ng is used for performing stress testing on the kernel. It allows you to exercise various physical subsystems of the computer, as well as interfaces of the OS kernel, using **stressors**. They are available for CPU, CPU cache, devices, I/O, interrupts, file system, memory, network, operating system, pipelines, schedulers, virtual machines. You may find the description of all the available stressors [here](https://www.mankier.com/1/stress-ng).

Running the netdev stressor (It starts N  workers  that  exercise  various  netdevice ioctl commands across all the available network devices. The ioctls exercised by this stressor are  as  follows: SIOCGIFCONF,  SIOCGIFINDEX, SIOCGIFNAME, SIOCGIFFLAGS, SIOCGIFADDR, SIOCGIFNETMASK, SIOCGIFMETRIC,  SIOCGIFMTU,  SIOCGIFHWADDR,  SIOCGIFMAP  and   SIOCGIFTXQLEN) using the `stress-ng --netdev 1 -t 60 --metrics` command.

![stress-ng --netdev 1 -t 60 --metrics output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/stress-ng-netdev.png)

We can use the perf record command to record the events and information associated with a process. This command records the profiling data in the perf.data file in the same directory. Lets record the events associated with the netdev stressor using the `./perf record stress-ng --netdev 1 -t 60 --metrics` command.

![perf record stress-ng ntdev output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-record-netdev.png)

To view the final report use the perf report command. This command helps us to read the perf.data file. The following image shows the output of the `./perf report` command and the events associated with the netdev stressor. 

![perf report for netdev events](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-report-netdev-events.png)

We can also use perf annotate to see the statistics of each instruction of the program. The following image shows the output of the `./perf annotate` command. 

![perf annotate output](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-annotate.png)

Using strace to collect the trace for netdev stressor. The following image shows the output of the  `strace -c  stress-ng --netdev 1 -t 60 --metrics` command.

![system calls made by netdev stressor](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/strace-netdev-stressor.png)

##### System Calls made by the workload:

The following table shows you the system calls, frequency and the Linux subsystem they fall under with links to their corresponding system call entry points with link to the Linux kernel repository.

| System Call | Frequency | Linux Subsystem | System Call Entry Point (API) |
| - | - | - | - |
| openat | 74 | Filesystem | [sys_openat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| close | 75 | Filesystem | [sys_close()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| read | 58 | Filesystem | [sys_read()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| fstat | 20 | Filesystem | [sys_fstat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| flock | 10 | Filesystem | [sys_flock()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| write | 7 | Filesystem | [sys_write()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getdents64 | 8 | Filesystem | [sys_getdents64()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| pread64 | 8 | Filesystem | [sys_pread64()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| lseek | 1 | Filesystem | [sys_lseek()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| access | 2 | Filesystem | [sys_access()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getcwd | 1 | Filesystem | [sys_getcwd()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| execve | 1 | Filesystem | [sys_execve()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| mmap | 61 | Memory Mgmt. | [sys_mmap()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| munmap | 3 | Memory Mgmt. | [sys_munmap()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| mprotect | 20 | Memory Mgmt. | [sys_mprotect()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| mlock | 2 | Memory Mgmt. | [sys_mlock()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| brk | 3 | Memory Mgmt. | [sys_brk()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigaction | 21 | Signal | [sys_rt_sigaction()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigprocmask | 1 | Signal | [sys_rt_sigprocmask()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| sigaltstack | 1 | Signal | [sys_sigaltstack()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigreturn | 1 | Signal | [sys_rt_sigreturn()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getpid | 8 | Process Mgmt. | [sys_getpid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| prlimit64 | 5 | Process Mgmt. | [sys_prlimit64()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| arch_prctl | 2 | Process Mgmt. | [sys_arch_prctl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| sysinfo | 2 | Process Mgmt. | [sys_sysinfo()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getuid | 2 | Process Mgmt. | [sys_getuid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| uname | 1 | Process Mgmt. | [sys_uname()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| setpgid | 1 | Process Mgmt. | [sys_setpgid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getrusage | 1 | Process Mgmt. | [sys_getrusage()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| geteuid | 1 | Process Mgmt. | [sys_geteuid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getppid | 1 | Process Mgmt. | [sys_getppid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| sendto | 3 | Network | [sys_sendto()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| connect | 1 | Network | [sys_connect()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| socket | 1 | Network | [sys_socket()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| clone | 1 | Process Mgmt. | [sys_clone()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| set_tid_address | 1 | Process Mgmt. | [sys_set_tid_address()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| wait4 | 2 | Time | [sys_wait4()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| alarm | 1 | Time | [sys_alarm()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| set_robust_list | 1 | Futex | [sys_set_robust_list()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |

#### paxtest

paxtest is a program that tests buffer overflows in the kernel. It tests kernel enforcements over memory usage. Generally, execution in some memory segments makes buffer overflows possible. It runs a set of programs that attempt to subvert memory usage. It is used as a regression test suite for PaX, but might be useful to test other memory protection patches for the kernel.

Running paxtest under the kiddie mode - `paxtest kiddie`

![paxtest under kiddie mode](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/paxtest-kiddie.png)

Collecting CPU stack traces for the paxtest kiddie command to see which function is calling other functions in the performance profile, using the DWARF method to unwind the stack. The following image shows the output of `./perf record --call-graph dwarf paxtest kiddie` command. 

![perf record paxtest kiddie](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-record-paxtest.png)

Reading the perf.data file. The following image shows the output of the `./perf report --stdio` command in the call-graph format. The stdio parameter shows the output in text format.

![paxtest events report](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/perf-report-paxtest-events.png)

Using strace to collect the trace when we run paxtest under kiddie mode. The following image shows the output of the `strace -c paxtest kiddie` command.

![paxtest under strace](Discovering_Linux_kernel_subsystems_used_by_a_workload_images/strace-paxtest.png)

##### System Calls made by the workload:
The following table shows you the system calls, frequency and the Linux subsystem they fall under with links to their corresponding system call entry points with link to the Linux kernel repository.

| System Call | Frequency | Linux Subsystem | System Call Entry Point (API) |
| - | - | - | - |
| read | 3 | Filesystem | [sys_read()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| write | 11 | Filesystem | [sys_write()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| close | 41 | Filesystem | [sys_close()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| stat | 24 | Filesystem | [sys_stat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| fstat | 2 | Filesystem | [sys_fstat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| pread64 | 6 | Filesystem | [sys_pread64()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| access | 1 | Filesystem | [sys_access()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| pipe | 1 | Filesystem | [sys_pipe()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| dup2 | 24 | Filesystem | [sys_dup2()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| execve | 1 | Filesystem | [sys_execve()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| fcntl | 26 | Filesystem | [sys_fcntl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| openat | 14 | Filesystem | [sys_openat()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigaction | 7 | Signal | [sys_rt_sigaction()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| rt_sigreturn | 38 | Signal | [sys_rt_sigreturn()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| clone | 38 | Process Mgmt. | [sys_clone()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| wait4 | 44 | Time | [sys_wait4()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| mmap | 7 | Memory Mgmt. | [sys_mmap()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| mprotect | 3 | Memory Mgmt. | [sys_mprotect()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| munmap | 1 | Memory Mgmt. | [sys_munmap()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| brk | 3 | Memory Mgmt. | [sys_brk()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getpid | 1 | Process Mgmt. | [sys_getpid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getuid | 1 | Process Mgmt. | [sys_getuid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getgid | 1 | Process Mgmt. | [sys_getgid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| geteuid | 2 | Process Mgmt. | [sys_geteuid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getegid | 1 | Process Mgmt. | [sys_getegid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| getppid | 1 | Process Mgmt. | [sys_getppid()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |
| arch_prctl | 2 | Process Mgmt. | [sys_arch_prctl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/syscalls.h) |

#### Conclusion
We hope this document has been informative and will help you as a guide on how to gather fine grained information on your workloads using **strace**.

#### References:
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/monitoring_and_managing_system_status_and_performance/index
https://copyfuture.com/blogs-details/20200102142905879jux966gmbab6shz
https://manpages.ubuntu.com/manpages/trusty/man1/paxtest.1.html
https://www.mankier.com/1/stress-ng <br>
https://habr.com/en/company/flant/blog/477994/

#### SPDX-License-Identifier: CC-BY-4.0
This document is released under the Creative Commons Attribution 4.0 International License, available at https://creativecommons.org/licenses/by/4.0/legalcode. Pursuant to Section 5 of the license, please note that the following disclaimers apply (capitalized terms have the meanings set forth in the license). To the extent possible, the Licensor offers the Licensed Material as-is and as-available, and makes no representations or warranties of any kind concerning the Licensed Material, whether express, implied, statutory, or other. This includes, without limitation, warranties of title, merchantability, fitness for a particular purpose, non-infringement, absence of latent or other defects, accuracy, or the presence or absence of errors, whether or not known or discoverable. Where disclaimers of warranties are not allowed in full or in part, this disclaimer may not apply to You.

To the extent possible, in no event will the Licensor be liable to You on any legal theory (including, without limitation, negligence) or otherwise for any direct, special, indirect, incidental, consequential, punitive, exemplary, or other losses, costs, expenses, or damages arising out of this Public License or use of the Licensed Material, even if the Licensor has been advised of the possibility of such losses, costs, expenses, or damages. Where a limitation of liability is not allowed in full or in part, this limitation may not apply to You.

The disclaimer of warranties and limitation of liability provided above shall be interpreted in a manner that, to the extent possible, most closely approximates an absolute disclaimer and waiver of all liability.









 


