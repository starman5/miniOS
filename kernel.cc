#include "kernel.hh"
#include "k-ahci.hh"
#include "k-apic.hh"
#include "k-chkfs.hh"
#include "k-chkfsiter.hh"
#include "k-devices.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"

// kernel.cc
//
//    This is the kernel


// # timer interrupts so far on CPU 0
std::atomic<unsigned long> ticks;

static void tick();
static void boot_process_start(pid_t pid, const char* program_name);


// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

void kernel_start(const char* command) {
    init_hardware();
    consoletype = CONSOLE_NORMAL;
    console_clear();

    // set up process descriptors
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i] = nullptr;
    }

    // start first process
    boot_process_start(1, CHICKADEE_FIRST_PROCESS);

    // start running processes
    cpus[0].schedule(nullptr);
}


// boot_process_start(pid, name)
//    Load application program `name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.
//    Only called at initial boot time.

void boot_process_start(pid_t pid, const char* name) {
    // look up process image in initfs
    memfile_loader ld(memfile::initfs_lookup(name), kalloc_pagetable());
    assert(ld.memfile_ && ld.pagetable_);
    int r = proc::load(ld);
    assert(r >= 0);

    // allocate process, initialize memory
    proc* p = knew<proc>();
    p->init_user(pid, ld.pagetable_);
    p->regs_->reg_rip = ld.entry_rip_;

    void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);
    vmiter(p, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);
    log_printf("before\n");
    uintptr_t console_page = 47104 - (47104 % 4096);
    log_printf("%p\n", console_page);
    log_printf("%p\n", ktext2pa(console));
    vmiter(p, console_page).try_map(ktext2pa(console), PTE_PWU);
    log_printf("after\n");
    p->regs_->reg_rsp = MEMSIZE_VIRTUAL;

    // add to process table (requires lock in case another CPU is already
    // running processes)
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[pid]);
        ptable[pid] = p;
    }

    // add to run queue
    cpus[pid % ncpu].enqueue(p);
}


// proc::exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the current CPU stack, then jumping to kernel assembly code (in
//    k-exception.S). That code transfers the state to the current kernel
//    task's stack, then calls proc::exception().

void proc::exception(regstate* regs) {
    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    //log_printf("proc %d: exception %d @%p\n", id_, regs->reg_intno, regs->reg_rip);

    // Record most recent user-mode %rip.
    if ((regs->reg_cs & 3) != 0) {
        recent_user_rip_ = regs->reg_rip;
    }

    // Show the current cursor location.
    consolestate::get().cursor();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER: {
        cpustate* cpu = this_cpu();
        if (cpu->cpuindex_ == 0) {
            tick();
        }
        lapicstate::get().ack();
        regs_ = regs;
        yield_noreturn();
        break;                  /* will not be reached */
    }

    case INT_PF: {              // pagefault exception
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if ((regs->reg_cs & 3) == 0) {
            panic_at(*regs, "Kernel page fault for %p (%s %s)!\n",
                     addr, operation, problem);
        }

        error_printf(CPOS(24, 0), 0x0C00,
                     "Process %d page fault for %p (%s %s, rip=%p)!\n",
                     id_, addr, operation, problem, regs->reg_rip);
        pstate_ = proc::ps_faulted;
        yield();
        break;
    }

    case INT_IRQ + IRQ_KEYBOARD:
        keyboardstate::get().handle_interrupt();
        break;

    default:
        if (sata_disk && regs->reg_intno == INT_IRQ + sata_disk->irq_) {
            sata_disk->handle_interrupt();
        } else {
            panic_at(*regs, "Unexpected exception %d!\n", regs->reg_intno);
        }
        break;                  /* will not be reached */

    }

    // return to interrupted context
}


// proc::syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value from `proc::syscall()` is returned to the user
//    process in `%rax`.

uintptr_t proc::syscall(regstate* regs) {
    //log_printf("proc %d: syscall %ld @%p\n", id_, regs->reg_rax, regs->reg_rip);

    // Record most recent user-mode %rip.
    recent_user_rip_ = regs->reg_rip;


    int start_canary = canary_;


    switch (regs->reg_rax) {

    case SYSCALL_CONSOLETYPE:
        if (consoletype != (int) regs->reg_rdi) {
            console_clear();
        }
        consoletype = regs->reg_rdi;
        return 0;

    case SYSCALL_PANIC:
        panic_at(*regs, "process %d called sys_panic()", id_);
        break;                  // will not be reached

    case SYSCALL_GETPID:
        return id_;
    
    case SYSCALL_GETPPID:
        return parent_id_;

    case SYSCALL_YIELD:
        yield();
        return 0;

    case SYSCALL_PAGE_ALLOC: {
        uintptr_t addr = regs->reg_rdi;
        if (addr >= VA_LOWEND/* || addr & 0xFFF*/) {
            return -1;
        }
        void* pg = kalloc(PAGESIZE);
        if (!pg || vmiter(this, addr).try_map(ka2pa(pg), PTE_PWU) < 0) {
            return -1;
        }

        return 0;
    }

    case SYSCALL_TEST_ALLOC: {
        uintptr_t addr = regs->reg_rdi;
        size_t sz = regs->reg_rsi;
        int order = msb(sz) - 1;

        if (addr >= VA_LOWEND || addr & 0xFF) {
            return -1;
        }

        log_printf("---- about to kalloc ---");
        void* pg = kalloc(sz);
        
        for (int i = 0; i < (1 << order); i += PAGESIZE) {
            if (!pg) {
                log_printf("!pg\n");
                return -1;
            }
                
            if (vmiter(this, addr + i).try_map(ka2pa(pg) + i, PTE_PWU) < 0) {
                //log_printf("can't map\n");
                return -1;
            }
        }
        // Given a certain probability, free the first page of memory
        //kfree(pg);
        //log_printf("after kfree\n");

        return 0;

    }

    case SYSCALL_WHATEVER_ALLOC: {
        //log_printf("beginning of syscall_whatever");
        uintptr_t addr = regs->reg_rdi;
        size_t sz = regs->reg_rsi;
        int order = msb(sz) - 1;

        if (addr >= VA_LOWEND || addr & 0xFFF) {
            //log_printf("bad addr\n");
            return -1;
        }

        void* pg = kalloc(sz);
        //log_printf("pg is %p. Will try to map to %p\n", pg, ka2pa(pg));

        for (int i = 0; i < (1 << order); i += PAGESIZE) {
            if (!pg) {
                log_printf("!pg\n");
            }
                
            if (vmiter(this, addr + i).try_map(ka2pa(pg) + i, PTE_PWU) < 0) {
                //log_printf("can't map\n");
                return -1;
            }
        }
        //log_printf("end of syscall whatever\n");
        return 0;
        /*if (!pg || vmiter(this, addr).try_map(ka2pa(pg), PTE_PWU) < 0) {
            return -1;
        }
        return 0;*/
    }
    case SYSCALL_EXIT: {
        // Remove the current process from the process table
        // Free all memory associated with the current process
            //ptable must be protected by lock
            //
        {
            log_printf("----- sys_exit on process %i\n", id_);
            spinlock_guard guard(ptable_lock);

            set_pagetable(early_pagetable);

            // free the stuff inside the pagetable
            // free the pagetable
            
            for (vmiter it(this->pagetable_, 0); it.va() < MEMSIZE_VIRTUAL; it.next()) {
                kfree((void*) it.va());
            }

            // remove the current process from the process table
            pagetable_ = nullptr;
        }
        

    }

    case SYSCALL_MSLEEP: {
        // use ticks atomic variable
        unsigned long wakeup_time = ticks + (regs->reg_rdi + 9) / 10;
        while (long(wakeup_time - ticks) > 0) {
            this->yield();
        }

        return 0;
    }

    case SYSCALL_MAP_CONSOLE: {
        uintptr_t addr = regs->reg_rdi;
        if (addr >= VA_LOWEND || addr & 0xFFF) {
            return -1;
        }

        if (vmiter (this, addr).try_map(CONSOLE_ADDR, PTE_PWU) < 0) {
            return -1;
        }
        return 0;
    }

    case SYSCALL_PAUSE: {
        sti();
        for (uintptr_t delay = 0; delay < 1000000; ++delay) {
            pause();
        }
        return 0;
    }

    case SYSCALL_FORK:
        return syscall_fork(regs);

    case SYSCALL_READ:
        return syscall_read(regs);

    case SYSCALL_WRITE:
        return syscall_write(regs);

    case SYSCALL_READDISKFILE:
        return syscall_readdiskfile(regs);

    case SYSCALL_SYNC: {
        int drop = regs->reg_rdi;
        // `drop > 1` asserts that no data blocks are referenced (except
        // possibly superblock and FBB blocks). This can only be ensured on
        // tests that run as the first process.
        if (drop > 1 && strncmp(CHICKADEE_FIRST_PROCESS, "test", 4) != 0) {
            drop = 1;
        }
        return bufcache::get().sync(drop);
    }

    case SYSCALL_NASTY: {
        int start_canary = canary_;
        // log_printf("start: %i\n", *(canary_ptr - 1));
        int nasty = syscall_nasty_alloc();
        assert(canary_ == start_canary);
        // log_printf("end: %i\n", *(canary_ptr-1));
        return 0;
    }

        

    default:
        // no such system call
        log_printf("%d: no such system call %u\n", id_, regs->reg_rax);
        return E_NOSYS;

    }

    int end_canary = canary_;
    assert(start_canary != end_canary);
    assert(start_canary == end_canary);
    assert(0 == 1);
}



// proc::syscall_fork(regs)
//    Handle fork system call.
//(void) regs;

int proc::syscall_fork(regstate* regs) {
    // Find the next available pid by looping through the ones already used
    pid_t parent_id = this->id_;

    proc* p = knew<proc>();
    if (p == nullptr) {
        log_printf("fork failure\n");
        return -1;
    }
    
    x86_64_pagetable* child_pagetable = kalloc_pagetable();
    if (child_pagetable == nullptr) {
        log_printf("fork failure\n");
        kfree(this);
        return -1;
    }

    int i = 1;
    {
        spinlock_guard guard(ptable_lock);
        for (; i < NPROC; i++) {
            
                if (ptable[i] == nullptr) {
                    break;
                }
            }
        
        if (i == NPROC) {
            log_printf("fork failure\n");
            kfree(this);
            return -1;
        }
        
        p->init_user((pid_t) i, child_pagetable);
    

        for (vmiter parentiter = vmiter(this, 0);
            parentiter.low();
            parentiter.next()) {
            
            vmiter childiter = vmiter(p, parentiter.va());

            if (parentiter.pa() == CONSOLE_ADDR) {
                if (childiter.try_map(parentiter.pa(), parentiter.perm()) == -1) {
                    log_printf("fork failure\n");
                    kfree(this);
                    return -1;
                }
            }
            
            else if (parentiter.user()) {
                void* addr = kalloc(PAGESIZE);
                if (addr == nullptr) {
                    log_printf("fork failure\n");
                    kfree(this);
                    return -1;
                }
                if (childiter.try_map(addr, parentiter.perm()) == -1) {
                    log_printf("fork failure\n");
                    kfree(this);
                    return -1;
                }
                memcpy(addr, (const void*) parentiter.va(), PAGESIZE);
                // ka2pa 
            }
        }
    
        memcpy(p->regs_, regs, sizeof(regstate));

        ptable[i] = p;

        p->regs_->reg_rax = 0;
        p->parent_id_ = parent_id;

        ptable[i]->pstate_ = ps_runnable;
        cpus[i % ncpu].enqueue(p);
    

    // return 0 to the child
    


    // mark it as runnable.  Maybe don't mark as runnable before all regs are set
    // because another cpu could run it with wrong registers
    }
            
    // return pid to the parent
    return i;

}


// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

int proc::syscall_nasty_alloc() {
    int evil_array[999];
    for (int i = 0; i < 999; i++) {
        evil_array[i] = 5;
    }

    if (evil_array[rand()] == 5) {
        return evil_array[rand()];
    }

    // If I modify the canary, the buffer overflow works!  But if I don't, it doesn't work.
    //canary_ = 100;
    //return 0;
}


uintptr_t proc::syscall_read(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.
    auto& kbd = keyboardstate::get();
    auto irqs = kbd.lock_.lock();

    // mark that we are now reading from the keyboard
    // (so `q` should not power off)
    if (kbd.state_ == kbd.boot) {
        kbd.state_ = kbd.input;
    }

    // yield until a line is available
    // (special case: do not block if the user wants to read 0 bytes)
    while (sz != 0 && kbd.eol_ == 0) {
        kbd.lock_.unlock(irqs);
        yield();
        irqs = kbd.lock_.lock();
    }

    // read that line or lines
    size_t n = 0;
    while (kbd.eol_ != 0 && n < sz) {
        if (kbd.buf_[kbd.pos_] == 0x04) {
            // Ctrl-D means EOF
            if (n == 0) {
                kbd.consume(1);
            }
            break;
        } else {
            *reinterpret_cast<char*>(addr) = kbd.buf_[kbd.pos_];
            ++addr;
            ++n;
            kbd.consume(1);
        }
    }

    kbd.lock_.unlock(irqs);
    return n;
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Write to open file `fd` (reg_rdi), rather than `consolestate`.
    // * Validate the write buffer.
    auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    size_t n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(addr);
        ++addr;
        ++n;
        console_printf(0x0F00, "%c", ch);
    }
    return n;
}

uintptr_t proc::syscall_readdiskfile(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    const char* filename = reinterpret_cast<const char*>(regs->reg_rdi);
    unsigned char* buf = reinterpret_cast<unsigned char*>(regs->reg_rsi);
    size_t sz = regs->reg_rdx;
    off_t off = regs->reg_r10;

    if (!sata_disk) {
        return E_IO;
    }

    // read root directory to find file inode number
    auto ino = chkfsstate::get().lookup_inode(filename);
    if (!ino) {
        return E_NOENT;
    }

    // read file inode
    ino->lock_read();
    chkfs_fileiter it(ino);

    size_t nread = 0;
    while (nread < sz) {
        // copy data from current block
        if (bcentry* e = it.find(off).get_disk_entry()) {
            unsigned b = it.block_relative_offset();
            size_t ncopy = min(
                size_t(ino->size - it.offset()),   // bytes left in file
                chkfs::blocksize - b,              // bytes left in block
                sz - nread                         // bytes left in request
            );
            memcpy(buf + nread, e->buf_ + b, ncopy);
            e->put();

            nread += ncopy;
            off += ncopy;
            if (ncopy == 0) {
                break;
            }
        } else {
            break;
        }
    }

    ino->unlock_read();
    ino->put();
    return nread;
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

static void memshow() {
    static unsigned long last_redisplay = 0;
    static unsigned long last_switch = 0;
    static int showing = 1;

    // redisplay every 0.04 sec
    if (last_redisplay != 0 && ticks - last_redisplay < HZ / 25) {
        return;
    }
    last_redisplay = ticks;

    // switch to a new process every 0.5 sec
    if (ticks - last_switch >= HZ / 2) {
        showing = (showing + 1) % NPROC;
        last_switch = ticks;
    }

    spinlock_guard guard(ptable_lock);

    int search = 0;
    while ((!ptable[showing]
            || !ptable[showing]->pagetable_
            || ptable[showing]->pagetable_ == early_pagetable)
           && search < NPROC) {
        showing = (showing + 1) % NPROC;
        ++search;
    }

    console_memviewer(ptable[showing]);
    if (!ptable[showing]) {
        console_printf(CPOS(10, 26), 0x0F00, "   VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}


// tick()
//    Called once every tick (0.01 sec, 1/HZ) by CPU 0. Updates the `ticks`
//    counter and performs other periodic maintenance tasks.

void tick() {
    // Update current time
    ++ticks;

    // Update display
    if (consoletype == CONSOLE_MEMVIEWER) {
        memshow();
    }
}
