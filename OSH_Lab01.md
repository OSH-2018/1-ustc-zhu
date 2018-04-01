# OSH-Lab01-Linux内核启动追踪

​																		祝冠琪-PB16060341

## 实验环境

1. Ubuntu 16.04
2. GDB-7.11.1
3. qemu-2.11.1
4. busybox-1.28.1



## 实验前准备

#### 1.busybox安装

先在官网上下载busybox-1.28.1.tar.bz2

```
tar -xf busybox-1.28.1.tar.bz2
make defconfig
make menucofig
#可能需要安装如下库
sudo apt-get install libncurses5-dev libncurses5-dbg libncurses5
```

#### 2.qemu安装

先在官网下载qemu-2.11.1

```
./configure
#如果出现error需要运行如下命令
sudo apt-get install git libglib2.0-dev libpixman-1-dev zlib1g-dev
#不知道为什么，科大源不能找到对应库，换到官方源才解决
make menuconfig
#这一步需要勾选Settings->Build Options->Build static binary(no share libs)
make
make install
```

#### 3.内核编译

先在kernel.org获取linux-4.15.13.tar.xz

```
tar -xf linux-4.15.13.tar.xz
make menuconfig
#选择Kernel hacking->Compile-time->checks and compiler options->Compile #the kernel with debug info
#选择64-Bit kernel
make
```

#### 4.busybox制作rootfs

```
cd _install
mkdir proc sys dev etc etc/init.d
touch etc/init.d/rcS
vim etc/init.d/rcS
```

编辑rcS中的内容

```
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
/sbin/mdev -s
```

接着

```
cd ..
chmod +x _install/etc/init.d/rcS
cd _install
find . | cpio -o --format=newc > ../rootfs.img
```



## 开始调试

在busybox目录下运行如下命令

```
qemu-system-x86_64 -kernel /home/zhuguanqi/linux-4.15.13/arch/x86/boot/bzImage -initrd rootfs.img -append "console=tty1 root=/dev/ram rdinit=sbin/init nokaslr "  -S -s
#注意此处需要加上nokaslr使能够在断点处停止
```

然后打开gdb,并在start_point处设置断点

```
gdb -tui
(gdb) file vmlinux 
(gdb) target remote:1234 
(gdb) break start_point
(gdb) c #运行到断点处
```

#### 1.start_kernel

![](https://github.com/OSH-2018/1-ustc-zhu/blob/master/png/start_kernel.png)

```
asmlinkage __visible void __init start_kernel(void)
{
	char *command_line;
	char *after_dashes;

	set_task_stack_end_magic(&init_task);
	smp_setup_processor_id();
	debug_objects_early_init();

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_disabled = true;

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 */
	boot_cpu_init();
	page_address_init();
	pr_notice("%s", linux_banner);
	setup_arch(&command_line);
	/*
	 * Set up the the initial canary and entropy after arch
	 * and after adding latent and command line entropy.
	 */
	add_latent_entropy();
	add_device_randomness(command_line, strlen(command_line));
	boot_init_stack_canary();
	mm_init_cpumask(&init_mm);
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	boot_cpu_state_init();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */

	build_all_zonelists(NULL);
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", boot_command_line);
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   NULL, set_init_arg);

	jump_label_init();

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	setup_log_buf(0);
	vfs_caches_init_early();
	sort_main_extable();
	trap_init();
	mm_init();

	ftrace_init();

	/* trace_printk can be enabled here */
	early_trace_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();
	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	radix_tree_init();

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
	workqueue_init_early();

	rcu_init();

	/* Trace events are available after this */
	trace_init();

	context_tracking_init();
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	init_IRQ();
	tick_init();
	rcu_init_nohz();
	init_timers();
	hrtimers_init();
	softirq_init();
	timekeeping_init();
	time_init();
	sched_clock_postinit();
	printk_safe_init();
	perf_event_init();
	profile_init();
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");
	early_boot_irqs_disabled = false;
	local_irq_enable();

	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	lockdep_info();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed.
	 */
	mem_encrypt_init();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	page_ext_init();
	kmemleak_init();
	debug_objects_mem_init();
	setup_per_cpu_pageset();
	numa_policy_init();
	acpi_early_init();
	if (late_time_init)
		late_time_init();
	calibrate_delay();
	pid_idr_init();
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
	thread_stack_cache_init();
	cred_init();
	fork_init();
	proc_caches_init();
	buffer_init();
	key_init();
	security_init();
	dbg_late_init();
	vfs_caches_init();
	pagecache_init();
	signals_init();
	proc_root_init();
	nsfs_init();
	cpuset_init();
	cgroup_init();
	taskstats_init_early();
	delayacct_init();

	check_bugs();

	acpi_subsystem_init();
	arch_post_acpi_subsys_init();
	sfi_init_late();

	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_free_boot_services();
	}

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

```



`start_kernel`函数的主要目的是完成内核初始化并启动祖先进程(1号进程)。在祖先进程启动之前`start_kernel`函数做了很多事情，如[锁验证器](https://www.kernel.org/doc/Documentation/locking/lockdep-design.txt),根据处理器标识ID初始化处理器，开启cgroups子系统，设置每CPU区域环境，初始化[VFS](http://en.wikipedia.org/wiki/Virtual_file_system) Cache机制，初始化内存管理，rcu,vmalloc,scheduler(调度器),IRQs(中断向量表),ACPI(中断可编程控制器)以及其它很多子系统。

在初始之初我们可以看见这两个变量

```
char *command_line
char *after_dashes
```

第一个变量表示内核命令行的全局指针，第二个变量将包含`parse_args`函数通过输入字符串中的参数'name=value'，寻找特定的关键字和调用正确的处理程序。

接下来我们可以看见`set_task_stack_end_magic(&init_task)`这个函数，由函数名可见这个函数是初始化了某个栈，让我们进入这个函数

#### 2.set_task_stack_end_magic(&init_task)

![](C:\Users\guanq\Desktop\png\set_task_stack_end_magic(&init_task).png)

```
set_task_stack_end_magic(struct task_struct *tsk)
{
	unsigned long *stackend;
  stackend = end_of_stack(tsk);
  *stackend = STACK_END_MAGIC;	/* for overflow detection */
}
```

可以看出此处设置了任务的堆栈。这个函数被定义在[kernel/fork.c](https://github.com/torvalds/linux/blob/master/kernel/fork.c#L297)功能为设置[canary](http://en.wikipedia.org/wiki/Stack_buffer_overflow) `init` 进程堆栈以检测堆栈溢出。其作用是先通过`end_of_stack`函数获取堆栈并赋给 `task_struct`。

#### 3.boot_cpu_init()

运用断点我们进入这个函数



![](C:\Users\guanq\Desktop\png\boot_cpu_init.png)

![](C:\Users\guanq\Desktop\png\boot_inside.png)

```
static void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();
	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);
}
```

此函数主要为了通过掩码初始化每一个CPU，首先我们需要获取当前处理器的ID通过下面函数：

```
int cpu = smp_processor_id();
```

返回的ID表示我们处于哪一个CPU上, `boot_cpu_init` 函数设置了CPU的在线, 激活, 当前的设置为:

```
set_cpu_online(cpu, true);
set_cpu_active(cpu, true);
set_cpu_present(cpu, true);
set_cpu_possible(cpu, true);
```

上述我们所有使用的这些CPU的配置我们称之为- CPU掩码`cpumask`. `cpu_possible` 则是设置支持CPU热插拔时候的CPU ID. `cpu_present` 表示当前热插拔的CPU. `cpu_online`表示当前所有在线的CPU以及通过 `cpu_present` 来决定被调度出去的CPU. CPU热插拔的操作需要打开内核配置宏`CONFIG_HOTPLUG_CPU`并且将 `possible == present` 以及`active == online`选项禁用。这些功能都非常相似，每个函数都需要检查第二个参数，如果设置为`true`，需要通过调用`cpumask_set_cpu` or `cpumask_clear_cpu`来改变状态。

#### 4.setup_arch(&command_line)

![](C:\Users\guanq\Desktop\png\setup_arch.png)

我们进入到指定的体系架构的初始函数，Linux 内核初始化体系架构相关调用`setup_arch`函数。`setup_arch`函数定义在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/setup.c) 文件中，此函数就一个参数-内核命令行。

#### 5.rest_init()

![](C:\Users\guanq\Desktop\png\rest_init.png)



```
static noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = kernel_thread(kernel_init, NULL, CLONE_FS);
	/*
	 * Pin init on the boot CPU. Task migration is not properly working
	 * until sched_init_smp() has been run. It will set the allowed
	 * CPUs for init to the non isolated CPUs.
	 */
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	/*
	 * Enable might_sleep() and smp_processor_id() checks.
	 * They cannot be enabled earlier because with CONFIG_PRREMPT=y
	 * kernel_thread() would trigger might_sleep() splats. With
	 * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
	 * already, but it's stuck on the kthreadd_done completion.
	 */
	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}
```

调用 rest_init()函数进行最后的初始化工作,包括创建1号进程(init),第一个内核线程等操作。最后，初始化结束。

## 实验总结

这一次实验，我在安装环境下踩了较多的坑，比如一开始编译成了32位的内核没有编译64位的内核，导致重新编译；busybox一开始制作的rootfs会导致panic；qemu版本过旧导致gdb调试出现玄学bug。通过这次实验，我对Linux内核有了一定的了解，更加熟悉了Linux的一些常用命令，并且更加锻炼了自己的耐心。
