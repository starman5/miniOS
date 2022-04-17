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
#define MIN_ORDER       12
#define MAX_ORDER       21

// # timer interrupts so far on CPU 0
std::atomic<unsigned long> ticks;
wait_queue sleep_wq;

static void tick();
static void boot_process_start(pid_t pid, const char* program_name);
static void init_first_process();
static void run_init();
static void setup_init_child();


int disk_vop_read(vnode* vn, uintptr_t addr, int sz) {
    log_printf("in disk_vop_read\n");
    // data will contain the inode*, which you can use to read
    chkfs::inode* ino = (chkfs::inode*) vn->vn_data_;
    //ino->lock_read();
    chkfs_fileiter it(ino);

    size_t nread = 0;
    while (nread < sz) {
        // copy data from current block
        if (bcentry* e = it.find(vn->vn_offset_).get_disk_entry()) {
            unsigned b = it.block_relative_offset();
            size_t ncopy;
            //if (!ino->truncated) {
            ncopy = min(
                size_t(ino->size - it.offset()),   // bytes left in file
                chkfs::blocksize - b,              // bytes left in block
                sz - nread                         // bytes left in request
            );
            //} else {
            //    ncopy = min(chkfs::blocksize - b, sz - nread);
            //}
            memcpy((void*)addr + nread, e->buf_ + b, ncopy);
            assert(e->ref_ != 0);
            e->put();

            nread += ncopy;
            vn->vn_offset_ += ncopy;
            if (ncopy == 0) {
                break;
            }
        } else {
            log_printf("in the weird else\n");
            break;
        }
    }

    //ino->unlock_read();
    //ino->put();
    return nread;
}

int disk_vop_write(vnode* vn, uintptr_t addr, int sz) {
    log_printf("in disk_vop_write\n");
    // data will contain the inode*, which you can use to write
    chkfs::inode* ino = (chkfs::inode*) vn->vn_data_;
    //ino->lock_write();
    chkfs_fileiter it(ino);

    size_t nwrite = 0;
    while (nwrite < sz) {
        if (bcentry* e = it.find(vn->vn_offset_).get_disk_entry()) {
            assert(e->ref_ > 0);
            unsigned b = it.block_relative_offset();
            size_t ncopy;
            //if (ino->size != 0) {
            //ncopy = min(
            //    size_t(ino->size - it.offset()),   // bytes left in file
            //    chkfs::blocksize - b,              // bytes left in block
            //    sz - nwrite                         // bytes left in request
            //);
            //} //else {
                ncopy = min(chkfs::blocksize - b, sz - nwrite);
                if (ino->size + ncopy > ino->size) {
                    ino->size += ncopy;
                };
            //}

            log_printf("%i, %i, %i\n", ino->size - it.offset(), chkfs::blocksize - b, sz - nwrite);

            e->get_write();
            memcpy(e->buf_ + b, (void*) addr + nwrite, ncopy);
            assert(e->ref_ != 0);
            e->put_write();
            e->put();

            nwrite += ncopy;
            vn->vn_offset_ += ncopy;
            if (ncopy == 0) {
                break;
            }
        }
        else {
            break;
        }
    }
    //ino->unlock_write();
    //ino->put();
    return nwrite;
}



int bbuffer::bbuf_read(char* buf, int sz) {
    log_printf("in bbuf read\n");
    log_printf("locked: %i\n", this->bbuffer_lock.is_locked());
    //auto lockthing = this->bbuffer_lock.lock();
    log_printf("grabbed the lock\n");
    if (this->write_closed_) {
        // EOF is returned when the pipe is drained
        log_printf("WriteCLosed\n");
    }
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
        log_printf("pos == 0 and sz > 0 and thiswrite\n");
        pos = -1;
    }
    //if (pos == 0 && sz > 0 && this->write_closed_) {
    //    log_printf("RET0\n");
    //    return 0;
    //}
    //this->bbuffer_lock.unlock(lockthing);
    return pos;
}

int bbuffer::bbuf_write(char* buf, int sz) {
    //auto irqs = this->bbuffer_lock.lock();
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
    log_printf("unlocking 1\n");
    //this->bbuffer_lock.unlock(irqs);
    if (pos == 0 && sz > 0) {
        log_printf("po is zero, sz > 0");
        return -1;
    }
    else {
        return pos;
    }
}


vnode* stdin_vnode;
vnode* stdout_vnode;
vnode* stderr_vnode;

vnode_ops* stdin_vn_ops;
vnode_ops* stdout_vn_ops;
vnode_ops* stderr_vn_ops;
vnode_ops* readend_pipe_vn_ops;
vnode_ops* writeend_pipe_vn_ops;
vnode_ops* disk_vn_ops;


int memfs_vop_read(vnode* vn, uintptr_t addr, int sz) {
    // memcpy stuff
    memfile* memf = (memfile*)vn->vn_data_;
    log_printf("%s\n", memf->data_ + vn->vn_offset_);
    memcpy((void*)addr, memf->data_ + vn->vn_offset_, sz);

    if (vn->vn_offset_ + sz > memf->len_) {
        int sz_read = memf->len_ - vn->vn_offset_;
        vn->vn_offset_ += sz_read;
        return sz_read;
    }   
    else {
        vn->vn_offset_ += sz;
        return sz;
    }
}

int memfs_vop_write(vnode* vn, uintptr_t addr, int sz) {
    // memcpy stuff
    if (vn->vn_offset_ + sz > ((memfile*)vn->vn_data_)->len_) {
        ((memfile*)vn->vn_data_)->set_length(((memfile*)vn->vn_data_)->len_ + (sz - vn->vn_offset_));
    }
    memcpy((void*)addr, vn->vn_data_, sz);
    return sz;
}

int stdout_write(vnode* vn, uintptr_t addr, int sz) {
    log_printf("in stdout write\n");
    auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    int n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(addr);
        ++addr;
        ++n;
        console_printf(0x0F00, "%c", ch);
    }

    log_printf("end stdout write\n");
    return n;

}

int stderr_write(vnode* vn, uintptr_t addr, int sz) {
    return 0;

}

int stdin_read(vnode* vn, uintptr_t addr, int sz) {
    log_printf("in stdin read\n");
    auto& kbd = keyboardstate::get();
    auto irqs = kbd.lock_.lock();

    // mark that we are now reading from the keyboard
    // (so `q` should not power off)
    if (kbd.state_ == kbd.boot) {
        kbd.state_ = kbd.input;
    }

    // yield until a line is available
    // (special case: do not block if the user wants to read 0 bytes)
    // block until sz == 0 and kbd.eol != 0
    // currently have the lock
    //waiter().block_until(kbd.keyboardstate_wq_, [&] () {
    //    return (sz == 0 || kbd.eol_ != 0);
    //}, kbd.lock_, irqs);
    log_printf("after blocking\n");

    while (sz != 0 && kbd.eol_ == 0) {
        kbd.lock_.unlock(irqs);
        current()->yield();
        irqs = kbd.lock_.lock();
    }

    // read that line or lines
    int n = 0;
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

int pipe_read(vnode* vn, uintptr_t buf, int sz) {
    log_printf("in pipe read\n");
    //log_printf("vn: %p\n", vn);
    bbuffer* pipe_buffer = (bbuffer*) vn->vn_data_;
    assert(vn->vn_data_);
    assert(pipe_buffer);
    log_printf("buf: %p\n", pipe_buffer);
    //log_printf("addr of buf: %p len: %i\n", pipe_buffer, pipe_buffer->blen_);
    //int ret = pipe_buffer->bbuf_read((char*) buf, sz);
    //while (ret == -1) {
    //    log_printf("buffer empty\n");
    //    current()->yield();
    //    ret = pipe_buffer->bbuf_read((char*) buf, sz);
    //}
    auto irqs = pipe_buffer->bbuffer_lock.lock();
    waiter w;
    int thing;
    log_printf("here\n");
    //log_printf("%p\n", w.wq_);
    w.block_until(pipe_buffer->bbuffer_wq_, [&] () {
        //log_printf("check\n");
        log_printf("closed: %i\n", pipe_buffer->write_closed_ == true);
        thing = pipe_buffer->bbuf_read((char*) buf, sz);
        return (thing != -1 or pipe_buffer->write_closed_ == true);
    }, pipe_buffer->bbuffer_lock, irqs);

    pipe_buffer->bbuffer_lock.unlock(irqs);
    return thing;

}

int pipe_write(vnode* vn, uintptr_t buf, int sz) {
    log_printf("in pipe write\n");
    assert(vn);
    bbuffer* pipe_buffer = (bbuffer*) vn->vn_data_;
    assert(pipe_buffer);
    //log_printf("addr of buf: %p len: %i\n", pipe_buffer, pipe_buffer->blen_);
    int writeret = pipe_buffer->bbuf_write((char*) buf, sz);
    //readpipe_wq.wake_all();
    while (writeret == -1) {
        log_printf("buffer full\n");
        current()->yield();
        writeret = pipe_buffer->bbuf_write((char*) buf, sz);
    }
    log_printf("before wake all\n");
    //log_printf("%p\n", pipe_buffer->bbuffer_wq_);
    pipe_buffer->bbuffer_wq_.wake_all();
    return writeret;
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

    stdin_vnode = knew<vnode>();
    stdout_vnode = knew<vnode>();
    stderr_vnode = knew<vnode>();


    stdin_vn_ops = knew<vnode_ops>();
    stdout_vn_ops = knew<vnode_ops>();
    stderr_vn_ops = knew<vnode_ops>();
    readend_pipe_vn_ops = knew<vnode_ops>();
    writeend_pipe_vn_ops = knew<vnode_ops>();
    //disk_vn_ops = knew<vnode_ops>();

    stdin_vn_ops->vop_read = stdin_read;
    stdin_vn_ops->vop_write = stdout_write;
    stdout_vn_ops->vop_read = stdin_read;
    stdout_vn_ops->vop_write = stdout_write;
    stderr_vn_ops->vop_read = stdin_read;
    stderr_vn_ops->vop_write = stdout_write;
    readend_pipe_vn_ops->vop_read = pipe_read;
    readend_pipe_vn_ops->vop_write = nullptr;
    writeend_pipe_vn_ops->vop_read = nullptr;
    writeend_pipe_vn_ops->vop_write = pipe_write;
    //disk_vn_ops->vop_read = disk_read;
    //disk_vn_ops->vop_write = disk_write;

    // Set up the vnodes
    stdin_vnode->vn_ops_ = stdin_vn_ops;
    stdout_vnode->vn_ops_ = stdout_vn_ops;
    stderr_vnode->vn_ops_ = stderr_vn_ops;

    init_first_process();

    // start first user process
    log_printf("booting first chickadee user process\n");
    boot_process_start(2, CHICKADEE_FIRST_PROCESS);

    setup_init_child();

    // Add file descriptors to the process' file descriptor table
    for (int i = 3; i < MAX_FDS; i++) {
        ptable[2]->vntable_[i] = nullptr;
    }

    // Add stdin, stdout, stderr to process' vnode table
    ptable[2]->vntable_[0] = stdin_vnode;
    ptable[2]->vntable_[1] = stdout_vnode;
    ptable[2]->vntable_[2] = stderr_vnode;

    // start running processes
    cpus[0].schedule(nullptr);
}

void setup_init_child() {
    //{
    //    spinlock_guard guard(ptable_lock);
        ptable[1]->children_.push_back(ptable[2]);
    //}
}

void init_first_process() {
    log_printf("in init_first_process\n");
    proc* p_init = nullptr;

    p_init = knew<proc>();
    p_init->init_kernel(1, run_init);
    //{
    //    spinlock_guard guard(ptable_lock);
        ptable[1] = p_init;
    //}
  
    //log_printf("about to schedule init_first_process on cpu 0.  id = %i, parent = %i\n", p_init->id_, p_init->parent_id_);
    // Smart to enqueue on cpu 0 because that will always be available, even at the very very beginning
    log_printf("end init_first_process\n");
    cpus[0].enqueue(p_init);
}

void run_init() {
    while (true) {
        //spinlock_guard guard(ptable_lock);
        if (!ptable[1]->children_.front()) {
            log_printf("halting\n");
            process_halt();
        }
        int* status;
        current()->syscall_waitpid(0, status, W_NOHANG);
        //log_printf("end run_init\n");
    }
}



// boot_process_start(pid, name)
//    Load application program `name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.
//    Only called at initial boot time.

void boot_process_start(pid_t pid, const char* name) {
    // look up process image in initfs
    log_printf("in boot process start\n");
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
    //uintptr_t console_page = 47104 - (47104 % 4096);
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
    log_printf("end boot process start\n");
    p->cpu_index_ = pid % ncpu;
    cpus[p->cpu_index_].enqueue(p);
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
    //log_printf("in proc exception\n");
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
    log_printf("proc %d: syscall %ld @%p\n", id_, regs->reg_rax, regs->reg_rip);

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
        log_printf("syscall page alloc\n");
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

    case SYSCALL_TESTKALLOC: {
        return syscall_testkalloc(regs);
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
        //log_printf("in waitpid\n");

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
            log_printf("----- sys_exit on process %i\n", id_);
            spinlock_guard guard(ptable_lock);
            log_printf("ptlock\n");
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
            log_printf("out of vmiter\n");

            assert(pagetable_ != early_pagetable);

            for (ptiter it(pagetable_); it.low(); it.next()) {
                it.kfree_ptp(); 
            }
            log_printf("out of ptiter\n");

            kfree(pagetable_);

            pagetable_ = early_pagetable;

        }

        //assert(!ptable[this->id_]);
        this->pstate_ = ps_exited;
        this->exit_status_ = regs->reg_rdi;
        //yield_noreturn();
        log_printf("outside lock\n");
        yield_noreturn();

    }

    case SYSCALL_MSLEEP: {
        int ticksoriginal = ticks;
        
        log_printf("in sleep\n");
        // use ticks atomic variable
        unsigned long wakeup_time = ticks + (regs->reg_rdi + 9) / 10;
        /*while (long(wakeup_time - ticks) > 0) {
            this->yield();
        }*/
        //log_printf("about to block\n");
        waiter().block_until(sleep_wq, [&] () {
            return (long(wakeup_time - ticks) <= 0);
        });
        //log_printf("difference: %i, expected: %i\n", ticks - ticksoriginal, regs->reg_rdi);
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

    case SYSCALL_EXECV: {
        return proc::syscall_execv(regs);
    }

    case SYSCALL_OPEN: {
        return proc::syscall_open(regs);
    }

    
    case SYSCALL_CLOSE: {
        log_printf("in sys_close\n");
        int fd = regs->reg_rdi;
        auto irqs = this->vntable_lock_.lock();
        log_printf("proc %i closing fd %i\n", this->id_, fd);
        log_printf("close: %p\n", bufcache::get().dirty_list_.front());
        if (fd < 0 or fd >= MAX_FDS or !this->vntable_[fd]) {
            log_printf("bad close\n");
            this->vntable_lock_.unlock(irqs);
            return E_BADF;
        }

        chkfs::inode* inod = (chkfs::inode*) vntable_[fd]->vn_data_;
        log_printf("closing block %i\n", inod->entry()->bn_);
        log_printf("vnref: %i\n", vntable_[fd]->vn_refcount_);
        log_printf("hi\n");
        assert(vntable_[fd]);
        assert(vntable_[fd]->vn_ops_);
        assert(vntable_[fd]->vn_ops_);
        if (this->vntable_[fd]->vn_ops_->vop_write == pipe_write) {
            assert((bbuffer*)this->vntable_[fd]->vn_data_);
            log_printf("CHANGetotrue\n");
            ((bbuffer*)this->vntable_[fd]->vn_data_)->write_closed_ = true;
        }
        log_printf("hiii\n");
        log_printf("%p\n", this->vntable_[fd]->vn_data_);
        if (this->vntable_[fd]->vn_data_ && this->vntable_[fd]->is_pipe) {
            ((bbuffer*)this->vntable_[fd]->vn_data_)->bbuffer_wq_.wake_all();
        }
        this->vntable_[fd]->vn_refcount_ -= 1;
        if (vntable_[fd]->vn_refcount_ == 0) {
            log_printf("donsdga\n");
            chkfs::inode* ino = (chkfs::inode*) vntable_[fd]->vn_data_;
            //if (ino->entry()->ref_ > 0) {
            ino->put();
        }
        this->vntable_[fd] = nullptr;
        log_printf("here\n");
        this->vntable_lock_.unlock(irqs);
        log_printf("after close: %p\n", bufcache::get().dirty_list_.front());
        
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
        //int start_canary = canary_;
        // log_printf("start: %i\n", *(canary_ptr - 1));
        int nasty = syscall_nasty_alloc();
        assert(canary_ == start_canary);
        // log_printf("end: %i\n", *(canary_ptr-1));
        return 0;
    }

    case SYSCALL_PIPE:
        return syscall_pipe(regs);

    case SYSCALL_LSEEK:
        return syscall_lseek(regs);

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

int proc::syscall_lseek(regstate* regs) {
    int fd = regs->reg_rdi;
    int off = regs->reg_rsi;
    int lseek_tag = regs->reg_rdx;

    chkfs::inode* ino = (chkfs::inode*) vntable_[fd]->vn_data_;
    //bcentry* e = ino->entry();
    if (lseek_tag == LSEEK_SET) {
        vntable_[fd]->vn_offset_ = off;
        return off;
    }
    else if (lseek_tag == LSEEK_CUR) {
        vntable_[fd]->vn_offset_ += off;
        return vntable_[fd]->vn_offset_;
    }
    else if (lseek_tag == LSEEK_SIZE) {
        return ino->size;
    }
    else {
        vntable_[fd]->vn_offset_ = ino->size + off;
        return vntable_[fd]->vn_offset_;
    }
}

int proc::syscall_execv(regstate* regs) {
    const char* filename = (const char*)regs->reg_rdi;
    const char* const* argv = (const char* const*)regs->reg_rsi;
    int argc = regs->reg_rdx;

    log_printf("about to validate\n");
    // Validate pathname
    if (!vmiter(pagetable_, (uintptr_t)filename).user() or !vmiter(pagetable_, (uintptr_t)filename).present()) {
        return E_FAULT;
    }

    // Validate argv
    if (argv[argc]) {
        return E_FAULT;
    }

    // memfile_loader ld(memfile::initfs_lookup(name), kalloc_pagetable());
    // assert(ld.memfile_ && ld.pagetable_);
    // int r = proc::load(ld);*/

    if (!sata_disk) {
        return E_IO;
    }

    auto ino = chkfsstate::get().lookup_inode(filename);
    if (!ino) {
        log_printf("bad\n");
        return E_NOENT;
    }

    x86_64_pagetable* new_pagetable = kalloc_pagetable();

    file_loader ld(ino, new_pagetable);
    log_printf("ld.pagetable_: %p\n", ld.pagetable_);
    assert(ld.ino_ && ld.pagetable_);
    int r = proc::load(ld);
    log_printf("buffer: %p\n", ld.buffer_);
    //assert(r >= 0);
    if (r < 0) {
        log_printf("no good bud\n");
        kfree(pagetable_);
        return r;
    }

    ino->put();
    log_printf("finished loading\n");

    void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);

    
    //log_printf("id: %i, parent_id: %i\n", p->id_, p->parent_id_);

    vmiter(new_pagetable, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);
    //uintptr_t console_page = 47104 - (47104 % 4096);
    vmiter(new_pagetable, ktext2pa(console)).map(CONSOLE_ADDR, PTE_PWU);

    x86_64_pagetable* old_pt = pagetable_;
    this->init_user(this->id_, new_pagetable);

    //this->regs_->reg_rip = memf_loader.entry_rip_;
    //this->regs_->reg_rsp = MEMSIZE_VIRTUAL;


    // Allocate and map a new stack page
   /* void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);
    vmiter(new_pagetable, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);

    // Map console
    vmiter(new_pagetable, ktext2pa(console)).try_map(ktext2pa(console), PTE_PWU);

    init_user(id_, new_pagetable);*/

    // vmiter representing top of the newly allocated stack
    vmiter it(new_pagetable, MEMSIZE_VIRTUAL);

    char* argpointers[argc];
    for (int i = 0; i < argc; i++) {
        // Subtract the length of the argument and leave room for null character
        // Right now, we are putting the characters themselves on the stack, so pointers
        // to the strings will be valid
        it -= (strlen(argv[i]) + 1);
        char* ptr = pa2kptr<char*>(it.pa());
        strcpy(ptr, argv[i]);
        argpointers[i] = (char*) it.va(); 
        //memcpy(it.kptr<char*>(), argv[i], strlen(argv[i]));   
    }

    //it -= (it.va() % sizeof(char*));

    it -= sizeof(char*);
    log_printf("d\n");

    // Insert nullptr at the last index in argpointers
    // char* ptr = knew<char>();
    // ptr = nullptr;
    // char* thing = (char*) it.va();
    // memcpy(thing, &ptr, sizeof(char*));
    memset(it.kptr<unsigned long*>(), 0, sizeof(char*));
    log_printf("e\n");

    for (int j = argc - 1; j >= 0; j--) {
        it -= sizeof(char*);
         char* dest = pa2kptr<char*>(it.pa());
         memcpy(dest, &argpointers[j], sizeof(char*));
        //*(it.kptr<unsigned long*>()) = argpointers[j];
    }

    log_printf("f\n");
    regs->reg_rip = ld.entry_rip_;
    //log_printf("hi\n");
    regs->reg_rsi = it.va();
    regs->reg_rdi = argc;
    regs->reg_rbp = MEMSIZE_VIRTUAL;
    log_printf("h\n");

    if (regs->reg_rsi % 16 == 0) {
        regs->reg_rsp = regs->reg_rsi - 8;
    }
    //log_printf("bud\n");

    else {
        regs->reg_rsp = regs->reg_rsi;
    }
    //log_printf("before setting pagetbale\n");
    set_pagetable(new_pagetable);
    log_printf("after\n");

    kfree(old_pt);

    //this->cpu_index_ = id_ % ncpu;
    //cpus[this->cpu_index_].enqueue(this);
    log_printf("end execv\n");
    yield_noreturn();
    assert(false);

}

int proc::syscall_open(regstate* regs) {
    log_printf("in open\n");
    const char* pathname = (const char*)regs->reg_rdi;
    int flags = regs->reg_rsi;

    if (!sata_disk) {
        return E_IO;
    }
    
    // Validate the name.  It is a char*.  Make sure it is not just some random pointer
    if (!pathname) {
        return E_FAULT;
    }

    log_printf("%p\n", pathname);
    if (!vmiter(pagetable_, (uintptr_t)pathname).present() or !vmiter(pagetable_, (uintptr_t)pathname).user()) {
        log_printf("not valid\n");
        return E_FAULT;
    }

    log_printf("not here\n");

    for (vmiter it(pagetable_, (uintptr_t) pathname); it.va() != 0; it++) {
        if (!it.present() or !it.user()) {
            return E_FAULT;
        }
        if (*((char*)it.va()) == '\0') {
            break;
        }
    }


    // Look up pathname
    // memfile m;
    // memfile* initfs_ar = m.initfs;

    // log_printf("didn't catch it\n");
    // int initfs_index = m.initfs_lookup(pathname, ((flags & OF_CREATE) == OF_CREATE));
    // if (initfs_index < 0) {
    //     return initfs_index;
    // }

    // //memfile current_memfile = initfs_ar[initfs_index];
    // memfile* current_memfile = knew<memfile>();
    // current_memfile = &initfs_ar[initfs_index];
    // log_printf("%s\n", current_memfile->data_);
    
    // if ((flags & OF_TRUNC) == OF_TRUNC) {
    //     log_printf("truncating\n");
    //     // set the file's length to zero
    //     current_memfile->set_length(0);
    // }

    auto ino = chkfsstate::get().lookup_inode(pathname);
    log_printf("break\n");

    if (!ino) {
        log_printf("!ino in open\n");
        // do stuff
    }

    if (flags & OF_TRUNC && flags & OF_WRITE) {
        ino->lock_write();
        ino->size = 0;
        //ino->truncated = true;
        ino->entry()->estate_ = bcentry::es_dirty;
        ino->unlock_write();
        bufcache::get().dirty_list_.push_back(ino->entry());
    }

    // create a vnode and do stuff
    // vnode* disk_vnode = nullptr;
    // disk_vnode = knew<vnode>();
    // disk_vnode->vn_data_ = ino;
    // disk_vnode->vn_ops_ = disk_vn_ops;

    auto irqs = vntable_lock_.lock();
    bool existsSpace = false;
    int newfd;
    for (int i = 0; i < MAX_FDS; i++) {
        if (!vntable_[i]) {
            existsSpace = true;
            newfd = i;
            vnode* new_vnode = knew<vnode>();
            vnode_ops* new_vn_ops = knew<vnode_ops>();
            if ((flags & OF_READ) != OF_READ) {
                new_vn_ops->vop_read = nullptr;
            }
            else {
                log_printf("can read\n");
                new_vn_ops->vop_read = disk_vop_read;
            }
            if ((flags & OF_WRITE) != OF_WRITE) {
                new_vn_ops->vop_write = nullptr;
            }
            else {
                new_vn_ops->vop_write = disk_vop_write;
            }

            new_vnode->vn_data_ = ino;
            // log_printf("%p\n", current_memfile);
            // log_printf("%s\n", ((memfile*)new_vnode->vn_data_)->data_);
            // log_printf("%p\n", new_vnode);

            new_vnode->vn_ops_ = new_vn_ops;

            vntable_[i] = new_vnode;
            //vntable_[i]->vn_refcount_ += 1;
            //log_printf("%s\n", ((*)vntable_[i]->vn_data_)->data_);
            //log_printf("%i\n", i);
            break;
        }
    }

    vntable_lock_.unlock(irqs);
    
    if (!existsSpace) {
        log_printf("bad\n");
        return E_NOSPC;
    }
    else {
        log_printf("%i\n", newfd);
        return newfd;
    }
}

uintptr_t proc::syscall_pipe(regstate* regs) {
    log_printf("in syscall pipe\n");
    auto irqs = this->vntable_lock_.lock();
    assert(this->vntable_[0]);
    assert(this->vntable_[1]);
    assert(this->vntable_[2]);

    bbuffer* new_buffer = knew<bbuffer>();
    vnode* readend_vnode = knew<vnode>();
    vnode* writeend_vnode = knew<vnode>();
  
    // Find closed file descriptor for read end
    int readfd;
    bool existsreadfd = false;
    for (int i = 0; i < MAX_FDS; i++) {
        if (!this->vntable_[i]) {
            readfd = i;
            this->vntable_[i] = readend_vnode;
            existsreadfd = true;
            break;
        }
    }
    if (!existsreadfd) { 
        this->vntable_lock_.unlock(irqs);
        return E_MFILE;
    }

    // Find closed file descriptor for write end
    int writefd;
    int existswritefd = false;
    for (int j = 0; j < MAX_FDS; j++) {
        if (!this->vntable_[j]) {
            writefd = j;
            this->vntable_[j] = writeend_vnode;
            existswritefd = true;
            break;
        }
    }
    if (!existswritefd) {
        this->vntable_lock_.unlock(irqs);
        return E_MFILE;
    }
    log_printf("writefd: %i\n", writefd);
    this->vntable_lock_.unlock(irqs);

    readend_vnode->vn_data_ = new_buffer;
    readend_vnode->vn_ops_ = readend_pipe_vn_ops;
    readend_vnode->other_end = writefd;
    readend_vnode->is_pipe = true;
    auto irqs2 = this->vntable_lock_.lock();
    this->vntable_[readfd] = readend_vnode;
    this->vntable_lock_.unlock(irqs2);

    writeend_vnode->vn_data_ = new_buffer;
    writeend_vnode->vn_ops_ = writeend_pipe_vn_ops;
    writeend_vnode->other_end = readfd;
    writeend_vnode->is_pipe = true;
    auto irqs3 = this->vntable_lock_.lock();
    this->vntable_[writefd] = writeend_vnode;
    this->vntable_lock_.unlock(irqs3);

    // Return the two fds concatenated.  Write end comes before read end
    uintptr_t returnValue = ((uintptr_t)(writefd) << 32) + (uintptr_t) readfd;
    log_printf("%i\n", returnValue);
    log_printf("%i\n", returnValue >> 32);
    //open_fds_lock.unlock(irqs);
    return returnValue;
}

int proc::syscall_dup2(regstate* regs) {
    log_printf("in dup2\n");
    int oldfd = regs->reg_rdi;
    int newfd = regs->reg_rsi;
    auto irqs = this->vntable_lock_.lock();
    log_printf("dup2 on oldfd %i, newfd %i\n", oldfd, newfd);
    if (newfd < 0 or newfd > MAX_FDS or oldfd < 0 or oldfd > MAX_FDS or !this->vntable_[oldfd]) {
        this->vntable_lock_.unlock(irqs);
        return E_BADF;
    }

    // At the newfd index in the system wide fd table should be the same vnode as that of the oldfd index
    vnode* old_vnode = this->vntable_[oldfd];
    this->vntable_[newfd] = old_vnode;
    log_printf("dup2 system_vn_table[newfd]: %p\n", old_vnode);
    this->vntable_lock_.unlock(irqs);

    return newfd;
}

// proc::syscall_fork(regs)
//    Handle fork system call.
//(void) regs;

int proc::syscall_fork(regstate* regs) {
    log_printf("in fork\n");
    // Find the next available pid by looping through the ones already used
    pid_t parent_id = this->id_;
    auto irqs = this->vntable_lock_.lock();
    log_printf("in fork vntable lock\n");
    vnode** vntable = this->vntable_;
    this->vntable_lock_.unlock(irqs);
    //log_printf("section 1\n");

    proc* p = knew<proc>();
    if (p == nullptr) {
        log_printf("fork failure\n");
        return -1;
    }
    //log_printf("a\n");
    
    x86_64_pagetable* child_pagetable = kalloc_pagetable();
    if (child_pagetable == nullptr) {
        log_printf("fork failure\n");
        kfree(p);
        return -1;
    }
    //log_printf("b\n");
    int i = 1;
    //log_printf("hi\n");
    {
        //log_printf("in\n");
        spinlock_guard guard(ptable_lock);
        //log_printf("a");
        for (; i < NPROC; i++) {
            //log_printf("here\n");
            
                if (ptable[i] == nullptr) {
                    //log_printf("created p %i\n", i);
                    break;
                }
            }
        //log_printf("i: %i, nproc: %i\n", i, NPROC);
        if (i == NPROC) {
            //log_printf("fork failure\n");
            kfree(p);
            return -1;
        }
        //log_printf("c\n");
        assert(p);
        p->init_user((pid_t) i, child_pagetable);
    
        //log_printf("sectino 2\n");
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
        //log_printf("after memcpy\n");

        ptable[i] = p;

        p->regs_->reg_rax = 0;
        p->parent_id_ = parent_id;

        auto irqs2 = this->vntable_lock_.lock();
        for (int ix = 0; ix < MAX_FDS; ix++) {
            if (vntable[ix]) {
                vntable[ix]->vn_refcount_ += 1;
            }
            p->vntable_[ix] = vntable[ix];
        }
        log_printf("fork end vntable lock\n");
        this->vntable_lock_.unlock(irqs2);

        //log_printf("about to push back child\n");
        assert(ptable[parent_id]);
        ptable[parent_id]->children_.push_back(p);

        assert(ptable[i]);
        ptable[i]->pstate_ = ps_runnable;
        p->cpu_index_ = i % ncpu;
        cpus[p->cpu_index_].enqueue(p);
    
    }

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
    //log_printf("in waitpid\n");
    {
        //log_printf("waitpid grabbed lock\n");
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
                            //log_printf("end waitpid\n");
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
                        //log_printf("end waitpid\n");
                        return E_CHILD;
                    }
                    //log_printf("pid not in ptable or not exited\n");
                    //log_printf("in waitpid\n");
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

                    if (zombies_exist[0] == 0) {
                        //log_printf("nothing to wait for\n");
                        if (options == W_NOHANG) {
                            //log_printf("end waitpid\n");
                            return E_AGAIN;
                        }
                        else {
                            goto block;
                        }
                    }
                    pid = zombies_exist[1];
                }

                else {
                    //log_printf("There are no children\n");
                    //log_printf("end waitpid\n");
                    return E_CHILD;
                }
            }
            
            if (status) {
                *status = ptable[pid]->exit_status_;
                //log_printf("after exit status set\n");
            }

                            
            // remove pid from ptable (set to nullptr) and from childrej
            //      Check how an available pid is looked for to make sure
            ptable[pid]->waited_ = true;
            ptable[pid] = nullptr;
            log_printf("end waitpid no error, not unlocked\n");
                            
            // Put the exit status and the pid in a register
        }
    
    log_printf("end of waitpid no error\n");

    return pid;

        block:
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
    //assert(vmiter(pagetable_, addr).present());
    /*for (vmiter it(pagetable_, addr); it.va() < it.va() + sz; ++it) {
        if (!(it.present())) {
            log_printf("sdf\n");
            return E_FAULT;
        }
    }*/

    //log_printf("after accessing registers\n");

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.
        auto irqs = this->vntable_lock_.lock();
        if (fd < 0 or fd >= MAX_FDS or !this->vntable_[fd]) {
            log_printf("bad read!!!\n");
            this->vntable_lock_.unlock(irqs);
            return E_BADF;
        }
    
        vnode* readfile = this->vntable_[fd];
        //log_printf("%p\n", readfile);
        //log_printf("%p\n", (memfile*)readfile->vn_data_);
        //log_printf("%s\n", ((memfile*)readfile->vn_data_)->data_);
        log_printf("Read: id %i, fd: %i, sz: %i\n", this->id_, fd, sz);

        int (*read_func)(vnode* vn, uintptr_t addr, int sz) = readfile->vn_ops_->vop_read;
        //assert(read_func);
        if (!read_func) {
            log_printf("!read_func\n");
            this->vntable_lock_.unlock(irqs);
            return E_BADF;
        }
        log_printf("after getting read_func\n");
        this->vntable_lock_.unlock(irqs);
        return read_func(readfile, addr, sz);

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

    //log_printf("Write, id: %i, fd = %i, sz = %i\n", this->id_, fd, sz);
    //assert(vmiter(pagetable_, addr).present());
    /*for (vmiter it(pagetable_, addr); it.va() < it.va() + sz; ++it) {
        if (!(it.present())) {
            log_printf("asdf\n");
            return E_FAULT;
        }
    }*/
    // Your code here!
    // * Write to open file `fd` (reg_rdi), rather than `consolestate`.
    // * Validate the write buffer.
    // auto irqs = this->fdtable_lock_.lock();
        auto irqs = this->vntable_lock_.lock();
        //log_printf("fd lock\n");
        if (fd < 0 or fd >= MAX_FDS or !this->vntable_[fd]) {
            log_printf("bad write!!!\n");
            this->vntable_lock_.unlock(irqs);
            return E_BADF;
        }

    //log_printf("before vntable_lock\n");
    //log_printf("vn lock\n");
    
        vnode* writefile = this->vntable_[fd];
        //log_printf("syscall_write system_vn_table[fd]: %p\n", writefile);
        //log_printf("%p\n", writefile->vn_ops_);
        auto write_func = writefile->vn_ops_->vop_write;
        if (!write_func) {
            log_printf("!write_func\n");
            this->vntable_lock_.unlock(irqs);
            return E_BADF;
        }

        if (writefile->is_pipe && writefile->other_end == -1) {
            this->vntable_lock_.unlock(irqs);
            return E_PIPE;
        }
        this->vntable_lock_.unlock(irqs);
        log_printf("end write\n");

        return write_func(writefile, addr, sz);
    //}

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

    //log_printf("heeer\n");
    const char* filename = reinterpret_cast<const char*>(regs->reg_rdi);
    unsigned char* buf = reinterpret_cast<unsigned char*>(regs->reg_rsi);
    size_t sz = regs->reg_rdx;
    off_t off = regs->reg_r10;

    if (!sata_disk) {
        //log_printf("bad\n");
        return E_IO;
    }
    //log_printf("about to read\n");

    // read root directory to find file inode number
    auto ino = chkfsstate::get().lookup_inode(filename);
    if (!ino) {
        //log_printf("bad\n");
        return E_NOENT;
    }

    //log_printf("looked up\n");
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
            assert(e->ref_ != 0);
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

int proc::syscall_testkalloc(regstate* regs) {
    int tcase = regs->reg_rdi; // type of test to run
    
    int num_allocs = 50; // number of allocations to make per test
    void* ptr_arr[num_allocs]; // ptr_arr to save, which will be freed afterwards

    switch (tcase) {
        case 0: { 
            log_printf("in case 0\n");

            // simple test case 1
            // straigforward pagesize allocations, followed by frees

            uint64_t sz = PAGESIZE;
            for (int i = 0; i < num_allocs; ++i) {
                ptr_arr[i] = kalloc(sz);
            }

            for (int i = 0; i < num_allocs; ++i) {
                kfree(ptr_arr[i]);
            }

            log_printf("======= TEST CASE [0] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;
        }

        case 1: { 

            // randomized general case 1
            // Multiples of PAGESIZE allocations
            // the order of the allocation is randomized
            // ranges between max order to min order

            int ro = 0;
            uint64_t sz = PAGESIZE;

            for (int i = 0; i < num_allocs; ++i) {
                ro = rand(MIN_ORDER, MAX_ORDER);
                sz = 1 << ro;
                ptr_arr[i] = kalloc(sz);
            }

            for (int i = 0; i < num_allocs; ++i) {
                kfree(ptr_arr[i]);
            }

            log_printf("======= TEST CASE [1] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;
        }

        case 2: { 

            // randomized general case 2
            // non-multiples of PAGESIZE
            // can range fom 4096 bytes to 2^21 bytes

            uint64_t sz;

            for (int i = 0; i < num_allocs; ++i) {
                sz = rand(1 << MIN_ORDER, 1 << MAX_ORDER);
                ptr_arr[i] = kalloc(sz);
            }

            for (int i = 0; i < num_allocs; ++i) {
                kfree(ptr_arr[i]);
            }
            log_printf("======= TEST CASE [2] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;
        }

        case 3: { 

            // randomized general case 3
            // smaller but randomized page size allocations
            // sz requested by random generator is constrained to 
            // smaller allocation sizes thus, more allocations overall

            uint64_t sz;
            for (int j = 0; j < 10; ++j) {
                for (int i = 0; i < num_allocs; ++i) {
                    sz = rand(1 << MIN_ORDER, 1 << (MAX_ORDER - 5));
                    ptr_arr[i] = kalloc(sz);
                }

                for (int i = 0; i < num_allocs; ++i) {
                    kfree(ptr_arr[i]);
                }
            }
            log_printf("======= TEST CASE [3] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;
        }
        // ----- SLAB ALLOCATOR TESTS -----
        case 4: {

            // slab allocator random test 1
            // sizes of only smaller slabs are allocated
            // we expect here that by the time 50 allocations are requested
            // the smaller slabs will be used up and larger slabs will be
            // allocated until those are used up as well, at which point the 
            // buddy allocator will take over

            for (int j = 0; j < 10; ++j) {
                uint64_t sz;
                for (int i = 0; i < num_allocs; ++i) {
                    sz = rand(1 << 2, 1 << 6);
                    ptr_arr[i] = kalloc(sz);
                }
                for (int i = 0; i < num_allocs; ++i) {
                    kfree(ptr_arr[i]);
                }
            }
            log_printf("======= {SLAB} TEST CASE [4] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;

        }

        case 5: {

            // randomized slab allocator test 2
            // now we start with the larger 512 byte allocation sizes
            // we expect that these chunks will be used up quickly and
            // then the buddy allocator will take over

            for (int j = 0; j < 10; ++j) {
                uint64_t sz;
                for (int i = 0; i < num_allocs; ++i) {
                    sz = rand(1 << 7, (1 << 9) - 8);
                    ptr_arr[i] = kalloc(sz);
                }
                for (int i = 0; i < num_allocs; ++i) {
                    kfree(ptr_arr[i]);
                }
            }
            log_printf("======= {SLAB} TEST CASE [5] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;
        }

        case 6: { 

            // randomized slab allocator test 3
            // we randomly switch between larger slab sizes and smaller
            // slab sizes untill the buddy allocator takes over

            for (int j = 0; j < 10; ++j) {
                uint64_t sz;
                for (int i = 0; i < num_allocs; ++i) {
                    sz = rand(1 << 2, (1 << 9)- 8);
                    ptr_arr[i] = kalloc(sz);
                }
                for (int i = 0; i < num_allocs; ++i) {
                    kfree(ptr_arr[i]);
                }
            }
            log_printf("======= {SLAB} TEST CASE [6] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;
        }

        case 7: {

            // randomized slab allocator test 4
            // here we switch constantly between the large slab, small slab
            // and the buddy allocator at the same time

            for (int j = 0; j < 10; ++j) {
                uint64_t sz;
                for (int i = 0; i < num_allocs; ++i) {
                    sz = rand(1 << 2, 1 << (MIN_ORDER + 2));
                    ptr_arr[i] = kalloc(sz);
                }
                for (int i = 0; i < num_allocs; ++i) {
                    kfree(ptr_arr[i]);
                }
            }
            log_printf("======= {SLAB} TEST CASE [7] for PROCESS [%d] COMPLETED =======\n", this->id_);
            break;
        }

        default: {
            // if an incorrect test case number is called
            log_printf("======= ERROR: Test case number %d not implemented  =======\n", tcase);
            break;
        }
    }
    return 0;
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
    //log_printf("sleep_wq: %p\n", &sleep_wq);
    sleep_wq.wake_all();

    // Update display
    if (consoletype == CONSOLE_MEMVIEWER) {
        memshow();
    }
}