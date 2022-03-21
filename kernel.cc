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
static void init_first_process();
static void run_init();
static void setup_init_child();


bbuffer* pipe_buffer;

int bbuffer::bbuf_read(char* buf, int sz) {
    int pos = 0;
    while (pos < sz && this->blen_ > 0) {
        int bspace;
        int spacecompare = bcapacity - this->bpos_;
        if (spacecompare < this->blen_) {
            bspace = spacecompare;
        }
        else {
            bspace = this->blen_;
        }

        int n;
        if (sz - pos < bspace) {
            n = sz - pos;
        }
        else {
            n = bspace;
        }

        memcpy(&buf[pos], &this->bbuf_[this->bpos_], n);
        this->bpos_ = (this->bpos_ + n) % bcapacity;
        this->blen_ -= n;
        pos += n;
    }
    if (pos == 0 && sz > 0 && !this->write_closed_) {
        return -1;
    }
    log_printf("pos: %i\n", pos);
    return pos;
}

int bbuffer::bbuf_write(char* buf, int sz) {
    int pos = 0;
    while (pos < sz && this->blen_ < bcapacity) {
        int bindex = (this->bpos_ + this->blen_) % bcapacity;
        
        int bspace;
        if (bcapacity - bindex < bcapacity - this->blen_) {
            bspace = bcapacity - bindex;
        }
        else {
            bspace = bcapacity - this->blen_;
        }

        int n;
        if (sz - pos < bspace) {
            n = sz - pos;
        }
        else {
            n = bspace;
        }

        memcpy(&this->bbuf_[bindex], &buf[pos], n);
        this->blen_ += n;
        pos += n;
        log_printf("pos: %i\n", pos);   
    }
    if (pos == 0 && sz > 0) {
        return -1;
    }
    else {
        return pos;
    }
}

vnode* system_vn_table[MAX_FDS];
vnode* vnode_page;
vnode_ops* vnode_ops_page;


vnode* stdin_vnode;
vnode* stdout_vnode;
vnode* stderr_vnode;
//vnode* readpipe_vnode;
//vnode* writepipe_vnode;

vnode_ops* stdin_vn_ops;
vnode_ops* stdout_vn_ops;
vnode_ops* stderr_vn_ops;
vnode_ops* readpipe_vn_ops;
vnode_ops* writepipe_vn_ops;


int stdout_write(uintptr_t addr, int sz) {
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

int stderr_write(uintptr_t addr, int sz) {

}

int stdin_read(uintptr_t addr, int sz) {
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
        current()->yield();
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

int pipe_read(uintptr_t buf, int sz) {
    return pipe_buffer->bbuf_read((char*) buf, sz);

}

int pipe_write(uintptr_t buf, int sz) {
    return pipe_buffer->bbuf_write((char*) buf, sz);

}


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

    pipe_buffer = (bbuffer*) kalloc(PAGESIZE);

    vnode_page = (vnode*) kalloc(PAGESIZE);
    vnode_ops_page = (vnode_ops*) kalloc(PAGESIZE);
    
    // Set up the vn_ops
    stdin_vnode = &vnode_page[0];
    stdout_vnode = &vnode_page[1];
    stderr_vnode = &vnode_page[2];
    //readpipe_vnode = &vnode_page[3];
    //writepipe_vnode = &vnode_page[4];

    stdin_vn_ops = &vnode_ops_page[0];
    stdout_vn_ops = &vnode_ops_page[1];
    stderr_vn_ops = &vnode_ops_page[2];
    readpipe_vn_ops = &vnode_ops_page[3];
    writepipe_vn_ops = &vnode_ops_page[4];

    stdin_vn_ops->vop_read = stdin_read;
    stdin_vn_ops->vop_write = stdout_write;
    stdout_vn_ops->vop_read = stdin_read;
    stdout_vn_ops->vop_write = stdout_write;
    stderr_vn_ops->vop_read = stdin_read;
    stderr_vn_ops->vop_write = stdout_write;
    readpipe_vn_ops->vop_read = pipe_read;
    readpipe_vn_ops->vop_write = nullptr;
    writepipe_vn_ops->vop_read = nullptr;
    writepipe_vn_ops->vop_write = pipe_write;

    // Set up the vnodes
    stdin_vnode->vn_ops_ = stdin_vn_ops;
    stdout_vnode->vn_ops_ = stdout_vn_ops;
    stderr_vnode->vn_ops_ = stderr_vn_ops;
    //readpipe_vnode->vn_ops_ = readpipe_vn_ops;
    //writepipe_vnode->vn_ops_ = writepipe_vn_ops;

    // Set up system wide vnode table with stdout, stdin, stderr vnodes
    system_vn_table[0] = stdin_vnode;
    system_vn_table[1] = stdout_vnode;
    system_vn_table[2] = stderr_vnode;

    init_first_process();

    // start first process
    log_printf("booting first chickadee user process\n");
    boot_process_start(2, CHICKADEE_FIRST_PROCESS);
        // Add file descriptors to the process' open file descriptor array
    for (int i = 0; i < 3; i++) {
        ptable[2]->open_fds_[i] = i;
    }
    for (int i = 3; i < MAX_FDS; i++) {
        ptable[2]->open_fds_[i] = -1;
    }

    setup_init_child();

    // start running processes
    cpus[0].schedule(nullptr);
}

void setup_init_child() {
    {
        spinlock_guard guard(ptable_lock);
        ptable[1]->children_.push_back(ptable[2]);
    }
}

void init_first_process() {
    log_printf("in init_first_process\n");
    proc* p_init = nullptr;

    p_init = knew<proc>();
    p_init->init_kernel(1, run_init);
    {
        spinlock_guard guard(ptable_lock);
        ptable[1] = p_init;
    }
  
    log_printf("about to schedule init_first_process on cpu 0.  id = %i, parent = %i\n", p_init->id_, p_init->parent_id_);
    // Smart to enqueue on cpu 0 because that will always be available, even at the very very beginning
    cpus[0].enqueue(p_init);
}

void run_init() {
  /*  if (!first) {
        if (!ptable[1]->children_.front()) {
            log_printf("halting\n");
            process_halt();
        }
    }*/
    while (true) {
        if (!ptable[1]->children_.front()) {
            log_printf("halting\n");
            process_halt();
        }
        int* status;
        current()->syscall_waitpid(0, status, W_NOHANG);
    }
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
    log_printf("id: %i, parent_id: %i\n", p->id_, p->parent_id_);

    void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);
    vmiter(p, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);
    uintptr_t console_page = 47104 - (47104 % 4096);
    vmiter(p, ktext2pa(console)).try_map(ktext2pa(console), PTE_PWU);

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
        //log_printf("test alloc syscall on %p\n", addr);
        if(addr >= VA_LOWEND) {
            //log_printf("addr >= VA_LOWEND\n");
            return -1;
        }

        void* pg = kalloc(PAGESIZE);
        if (!pg || vmiter(this, addr).try_map(ka2pa(pg), PTE_PWU) < 0) {
            //log_printf("time to free\n");
            return -1;
        }

        return 0;
    }  

    case SYSCALL_TEST_FREE: {
        //log_printf("in test free bruh\n");
        //log_printf("%p\n", regs_);
        uintptr_t stack_bottom = regs->reg_rdi;
        //log_printf("heap top: %p\n", heap_top);
        uintptr_t heap_top = regs->reg_rsi;
        //log_printf("stack bottom: %p\n", stack_bottom);
        for (vmiter it(pagetable_, 0); it.low(); it.next()) {
            //log_printf("heap top: %p\n", heap_top);
            //log_printf("stack bottom: %p\n", stack_bottom);
            //log_printf("va: %p\n", it.va());
            if (it.user() && it.va() != CONSOLE_ADDR && it.va() >= heap_top && it.va() < stack_bottom) {  //it.va() >= heap_top && it.va() < stack_bottom) {
                // CHANGE WHEN VARIABLE SIZE IS SUPPORTED
                //log_printf("calling kfree on %p associated with va %p\n", it.pa(), it.va());
                it.kfree_page();
            }
        }
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

    case SYSCALL_WAITPID: {
        //log_printf("before waitpid\n");

        pid_t pid = regs->reg_rdi;
        int* status = (int*) regs->reg_rsi;
        //log_printf("after status\n");
        int options = regs->reg_rdx;
        //log_printf("after options\n");

        return syscall_waitpid(pid, status, options);

    }

    case SYSCALL_EXIT: {
        // Remove the current process from the process table
        // Free all memory associated with the current process
            //ptable must be protected by lock
        {
            //log_printf("----- sys_exit on process %i\n", id_);
            spinlock_guard guard(ptable_lock);
            assert(ptable[this->id_] != nullptr);

            //log_printf("before first child\n");
            /*if (this->children_.front()) {
                proc* first_child = this->children_.pop_front();
                first_child->parent_id_ = 1;
                this->children_.push_back(first_child);
                //log_printf("after first child\n");
            
                proc* child = this->children_.pop_front();
                while (child != first_child) {
                    child->parent_id_ = 1;
                    this->children_.push_back(child);
                    child = this->children_.pop_front();
                }
            }*/

            if (this->children_.front()) {
                proc* child = this->children_.pop_front();
                while (child) {
                    child->parent_id_ = 1;
                    ptable[1]->children_.push_back(child);
                    child = this->children_.pop_front();
                }
            }

            //ptable[this->id_] = nullptr;

            //log_printf("early pagetable: %p\n", early_pagetable);
            
            set_pagetable(early_pagetable);
            
            //log_printf("successfully set_pagetable to %p\n", early_pagetable);
            //log_printf("pagetable_: %p\n", pagetable_);
            
            //log_printf("Process' pagetable: %p\n", this->pagetable_);

            for (vmiter it(pagetable_, 0); it.low(); it.next()) {
                if (it.user() && it.va() != CONSOLE_ADDR) {
                    //kfree(it.kptr());
                    it.kfree_page();
                }
            }
            //log_printf("out of vmiter\n");

            assert(pagetable_ != early_pagetable);

            for (ptiter it(pagetable_); it.low(); it.next()) {
                it.kfree_ptp(); 
            }
            //log_printf("out of ptiter\n");

            kfree(pagetable_);

            pagetable_ = early_pagetable;

        }

        //assert(!ptable[this->id_]);
        this->pstate_ = ps_exited;
        this->exit_status_ = regs->reg_rdi;
        //yield_noreturn();
        //log_printf("outside lock\n");
        yield_noreturn();

    }

    case SYSCALL_MSLEEP: {
        //log_printf("in sleep\n");
        // use ticks atomic variable
        unsigned long wakeup_time = ticks + (regs->reg_rdi + 9) / 10;
        while (long(wakeup_time - ticks) > 0) {
            this->yield();
        }
        //log_printf("after sleep\n");

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

    /*case SYSCALL_OPEN: {
        // Find the next available fd
        int fd;
        for (; fd < MAX_FDS; fd++) {
            if (this->open_fds_[fd] != -1) {
                break;
            }
        }

        this->open_fds_[fd] = fd;

        // Update the system wide vnode table.
        // I think what the vnode is should depend on the flags set in syscall open
        // Maybe some kind of switch statement
        //system_vn_table[fd] = 

        return fd;
    }*/
    
    case SYSCALL_CLOSE: {
        int fd = regs->reg_rdi;
        log_printf("closing fd %i\n", fd);
        if (fd < 0 or fd >= MAX_FDS or this->open_fds_[fd] == -1) {
            return E_BADF;
        }
        
        // delete vnode in system wide structure, then set index to -1.
        // reset the refcount to 1, offset to 0, pointers to nullptr
        // vnode* vn_closing = system_vn_table[fd];
        // vn_closing->vn_refcount_ = 1;
        // vn_closing->vn_offset_ = 0;
        // vn_closing->vn_data_ = nullptr;
        // vn_closing->vn_ops_ = nullptr;

        system_vn_table[fd] = nullptr;

        this->open_fds_[fd] = -1;
        
        return 0;
    }

    case SYSCALL_DUP2:
        return syscall_dup2(regs);

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

    case SYSCALL_PIPE:
        return syscall_pipe(regs);

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

uintptr_t proc::syscall_pipe(regstate* regs) {
    log_printf("in syscall pipe\n");
    assert(this->open_fds_[0] != -1);
    assert(this->open_fds_[1] != -1);
    assert(this->open_fds_[2] != -1);
    int readfd;
    bool existsreadfd = false;
    for (int i = 0; i < MAX_FDS; i++) {
        if (this->open_fds_[i] == -1) {
            readfd = i;
            this->open_fds_[i] = i;
            existsreadfd = true;
            break;
        }
    }
    if (!existsreadfd) {
        return E_MFILE;
    }
    log_printf("readfd: %i\n", readfd);

    assert(this->open_fds_[0] != -1);
    assert(this->open_fds_[1] != -1);
    assert(this->open_fds_[2] != -1);
    int writefd;
    int existswritefd = false;
    for (int j = 0; j < MAX_FDS; j++) {
        if (this->open_fds_[j] == -1) {
            writefd = j;
            this->open_fds_[j] = j;
            existswritefd = true;
            break;
        }
    }
    if (!existswritefd) {
        return E_MFILE;
    }
    log_printf("writefd: %i\n", writefd);

    // Create a new vnode and set vnode_ops to readpipe_vn_ops
    // Look through vnode_page to find first empty entry
    for (int k = 0; k < (PAGESIZE / sizeof(vnode)); k++) {
        if (!vnode_page[k].vn_ops_) {
            vnode_page[k].vn_ops_ = readpipe_vn_ops;
            system_vn_table[readfd] = &vnode_page[k];
            log_printf("pipe system_vn_table[readfd]: %p\n", &vnode_page[k]);
            break;
        }
    }

    for (int l = 0; l < (PAGESIZE / sizeof(vnode)); l++) {
        if (!vnode_page[l].vn_ops_) {
            vnode_page[l].vn_ops_ = writepipe_vn_ops;
            system_vn_table[writefd] = &vnode_page[l];
            log_printf("pipe system_vn_table[writefd]: %p\n", &vnode_page[l]);
            break;
        }
    }

    // Return the two fds concatenated.  Write end comes before read end
    uintptr_t returnValue = ((uintptr_t)(writefd) << 32) + (uintptr_t) readfd;
    log_printf("%i\n", returnValue);
    log_printf("%i\n", returnValue >> 32);
    return returnValue;
}

int proc::syscall_dup2(regstate* regs) {
    int oldfd = regs->reg_rdi;
    int newfd = regs->reg_rsi;
    log_printf("dup2 on oldfd %i, newfd %i\n", oldfd, newfd);
    if (open_fds_[oldfd] == -1 or newfd < 0 or newfd > MAX_FDS or oldfd < 0 or oldfd > MAX_FDS) {
        return E_BADF;
    }

    // if (open_fds_[newfd] != -1) {
    //     system_vn_table[newfd] = nullptr;
    // }

    // At the newfd index in the system wide fd table should be the same vnode as that of the oldfd index
    vnode* old_vnode = system_vn_table[oldfd];
    system_vn_table[newfd] = old_vnode;
    log_printf("dup2 system_vn_table[newfd]: %p\n", old_vnode);
    this->open_fds_[newfd] = newfd;

    return newfd;
}

// proc::syscall_fork(regs)
//    Handle fork system call.
//(void) regs;

int proc::syscall_fork(regstate* regs) {
    log_printf("in fork\n");
    // Find the next available pid by looping through the ones already used
    pid_t parent_id = this->id_;
    int* fdtable = this->open_fds_;

    proc* p = knew<proc>();
    if (p == nullptr) {
        log_printf("fork failure\n");
        return -1;
    }
    
    x86_64_pagetable* child_pagetable = kalloc_pagetable();
    if (child_pagetable == nullptr) {
        log_printf("fork failure\n");
        kfree(p);
        return -1;
    }

    int i = 1;
    {
        spinlock_guard guard(ptable_lock);
        for (; i < NPROC; i++) {
            
                if (ptable[i] == nullptr) {
                    log_printf("created p %i\n", i);
                    break;
                }
            }
        
        if (i == NPROC) {
            log_printf("fork failure\n");
            kfree(p);
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
                    kfree(p);
                    return -1;
                }
            }

            else if (parentiter.user()) {
                void* addr = kalloc(PAGESIZE);
                if (addr == nullptr) {
                    log_printf("fork failure\n");
                    kfree(p);
                    return -1;
                }
                if (childiter.try_map(addr, parentiter.perm()) == -1) {
                    log_printf("fork failure\n");
                    kfree(p);
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
        
        // copy over per process file descriptor table from parent
        for (int i = 0; i < MAX_FDS; i++) {
            p->open_fds_[i] = fdtable[i];
        }

        log_printf("about to push back child\n");
        ptable[parent_id]->children_.push_back(p);

        ptable[i]->pstate_ = ps_runnable;
        cpus[i % ncpu].enqueue(p);
    

    // return 0 to the child
    


    // mark it as runnable.  Maybe don't mark as runnable before all regs are set
    // because another cpu could run it with wrong registers
    }
            
    // return pid to the parent
    log_printf("end of fork\n");
    return i;

}


// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

int* proc::check_exited(pid_t pid, bool condition) {
            assert(pid == 0);
            bool zombies_exist = false;
            if (this->children_.front()) {
                proc* first_child = this->children_.pop_front();
                this->children_.push_back(first_child);
                proc* child = this->children_.pop_front();
                while (child != first_child) {
                    if (child->pstate_ == ps_exited) {
                        //log_printf("id %i, ps_exited\n", child->id_);
                        zombies_exist = true;
                        pid = child->id_;
                        if (!condition) {
                            this->children_.push_back(child);
                        }
                        break;
                    }
                    this->children_.push_back(child);
                    child = this->children_.pop_front();
                }
                if (child == first_child) {
                    if (child->pstate_ == ps_exited) {
                        //log_printf("zombies is true\n");
                        zombies_exist = true;
                        pid = child->id_;
                        if (!condition) {
                            this->children_.push_back(child);
                        }
                    }
                    else {
                        //log_printf("restore\n");
                        this->children_.push_back(child);
                    }
                }
            }
            static int return_value[2];
            return_value[0] = zombies_exist;
            return_value[1] = pid;
            //log_printf("zombies_exist: %i, pid: %i\n", zombies_exist, pid);
            return return_value;
}

int proc::syscall_waitpid(pid_t pid, int* status, int options) {
    //log_printf(" --- In waitpid.  Current process: %i, Pid argument: %i\n", this->id_, pid);
    //log_printf("--- in waitpid\n");
    // The assertion below is stupid because pid could be 0 many many times
    //assert(ptable[pid]);
    {
        spinlock_guard guard(ptable_lock);

            // Specifying a pid
            if (pid != 0) {
                if (ptable[pid] && ptable[pid]->pstate_ == ps_exited) {
                    //log_printf("ptable pid and ps_exited\n");
                    this->children_.erase(ptable[pid]);
                }

                else {
                    if (ptable[pid]) {
                        //log_printf("not ps_exited\n");
                        if (options == W_NOHANG) {
                            return E_AGAIN;
                        }
                        else {
                            //log_printf("ptable[pid] before goto: %p\n", ptable[pid]);
                            // block until its ps_exited, then call proc::syscall_waitpid
                            goto block;
                        }
                    }
                    else {
                        //log_printf("not ptable\n");
                        return E_CHILD;
                    }
                    //log_printf("pid not in ptable or not exited\n");
                    return E_AGAIN;
                }
            }

            // Not specifying a pid
            else {
                //log_printf("Not specifying a pid\n");

                // Print out children of the proces that is waiting, for debugging purposes
                if (this->children_.front()) {
                    proc* first_child = this->children_.pop_front();
                    //log_printf("child id: %i\n", first_child->id_);
                    this->children_.push_back(first_child);
                    proc* child = this->children_.pop_front();
                    while (child != first_child) {
                        //log_printf("child id: %i\n", child->id_);
                        this->children_.push_back(child);
                        child = this->children_.pop_front();
                    }
                    if (child == first_child) {
                        this->children_.push_back(child);
                    }
                }
                if (this->children_.front()) {
                    int* zombies_exist = check_exited(pid, true);
                    //log_printf("zombies_exist addr: %p\n", zombies_exist);
                    //log_printf("zombies_exist: %i\n", zombies_exist[0]);
                    //log_printf("pid: %i\n", zombies_exist[1]);
                
                // // Check all processes in ptable to see if one has exited and needs to be reaped
                // //log_printf("0 pid\n");
                // bool zombies_exist = false;
                // if (this->children_.front()) {
                //     proc* first_child = this->children_.pop_front();
                //     this->children_.push_back(first_child);
                //     proc* child = this->children_.pop_front();
                //     while (child != first_child) {
                //         if (child->pstate_ == ps_exited) {
                //             log_printf("id %i, ps_exited\n", child->id_);
                //             zombies_exist = true;
                //             pid = child->id_;
                //             //this->children_.push_back(child);
                //             break;
                //         }
                //         this->children_.push_back(child);
                //         child = this->children_.pop_front();
                //     }
                //     if (child == first_child) {
                //         if (child->pstate_ == ps_exited) {
                //             zombies_exist = true;
                //             pid = child->id_;
                //         }
                //         else {
                //         log_printf("restore\n");
                //         this->children_.push_back(child);
                //         }
                //     }
                    

                    //log_printf("outside loop\n");

                    if (zombies_exist[0] == 0) {
                        //log_printf("nothing to wait for\n");
                        if (options == W_NOHANG) {
                            return E_AGAIN;
                        }
                        else {
                            //goto tryagain;
                            goto block;
                        }
                    }
                    pid = zombies_exist[1];
                }

                else {
                    //log_printf("There are no children\n");
                    return E_CHILD;
                }
            }
            
            
            //log_printf("got here\n");
            //log_printf("pid: %i\n", pid);
            //log_printf("pointer: %p\n", ptable[pid]);
            // Store the exit status inside *status
            if (status) {
                *status = ptable[pid]->exit_status_;
                //log_printf("after exit status set\n");
            }

                            
            // remove pid from ptable (set to nullptr) and from childrej
            //      Check how an available pid is looked for to make sure
            ptable[pid]->waited_ = true;
            ptable[pid] = nullptr;
                            
            // Put the exit status and the pid in a register
        }
    
    //log_printf("end of waitpid\n");

    return pid;

        block:
        //log_printf("ptable after block: %p\n", ptable[pid]);
        //{
            //spinlock_guard guard(ptable_lock);
            //log_printf("Block Here\n");
            //log_printf("ptable[pid]: %p\n", ptable[pid]);
            if (pid != 0) {
                while (ptable[pid]->pstate_ != ps_exited) {
                    this->yield();
                }
            }
            
            else {
                while (check_exited(pid, false)[0] == false) {
                    this->yield();
                }
            }
        //}
        return syscall_waitpid(pid, status, options);


}

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
    log_printf("In syscall_read\n");

    int fd = regs->reg_rdi;
    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    log_printf("after accessing registers\n");

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.
    if (fd < 0 or fd >= MAX_FDS or this->open_fds_[fd] == -1) {
        return E_BADF;
    }
    vnode* readfile = system_vn_table[fd];
    log_printf("fd: %i, sz: %i\n", fd, sz);
    // Call the read vn_op
    log_printf("readfile: %p\n", readfile);
    log_printf("readfile->vn_ops_: %p\n", readfile->vn_ops_);
    log_printf("vopread: %p\n", readfile->vn_ops_->vop_read);
    int (*read_func)(uintptr_t addr, int sz) = readfile->vn_ops_->vop_read;
    if (!read_func) {
        return E_BADF;
    }
    log_printf("after getting read_func\n");
    return read_func(addr, sz);

    /*auto& kbd = keyboardstate::get();
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
    return n;*/
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    int fd = regs->reg_rdi;
    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    log_printf("In syscall write, fd = %i, sz = %i\n", fd, sz);

    // Your code here!
    // * Write to open file `fd` (reg_rdi), rather than `consolestate`.
    // * Validate the write buffer.

    if (this->open_fds_[fd] == -1 or fd < 0 or fd >= MAX_FDS) {
        return E_BADF;
    }
    vnode* writefile = system_vn_table[fd];
    log_printf("syscall_write system_vn_table[fd]: %p\n", writefile);
    log_printf("%p\n", writefile->vn_ops_);
    auto write_func = writefile->vn_ops_->vop_write;
    if (!write_func) {
        return E_BADF;
    }
    return write_func(addr, sz);

    /*auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    size_t n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(addr);
        ++addr;
        ++n;
        console_printf(0x0F00, "%c", ch);
    }
    return n;*/
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
