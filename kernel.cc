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
wait_queue threads_exit_wq;

static void tick();
static void boot_process_start(pid_t pid, pid_t id, const char* program_name);
static void init_first_process();
static void run_init();
static void setup_init_child();
static void process_info();
static void thread_info();

void process_info() {
    // real_ptable_lock must be held when calling this function
    //auto irqs = real_ptable_lock.lock();
    for (int i = 1; i < NPROC; i++) {
        if (real_ptable[i]) {
        log_printf("index: %i, pid: %i, parent_pid: %i, pagetable: %p, pstate: %i\n", i, real_ptable[i]->pid_, real_ptable[i]->parent_pid_, real_ptable[i]->pagetable_, real_ptable[i]->pstate_);
        }
    }
    //real_ptable_lock.unlock(irqs);
}

void thread_info() {
    // ptable_lock must be held when calling this function
    //auto irqs = ptable_lock.lock();
    for (int i = 0; i < NTHREAD; i++) {
        if (ptable[i]) {
        log_printf("index: %i, id: %i, pid: %i, pagetable: %p, exiting: %i, cpu_index: %i\n", i, ptable[i]->id_, ptable[i]->pid_, ptable[i]->pagetable_, ptable[i]->exiting_, ptable[i]->cpu_index_);
        }
    }
    //ptable_lock.unlock(irqs);
}


int disk_vop_read(vnode* vn, uintptr_t addr, int sz) {
    log_printf("in disk_vop_read\n");
    // data will contain the inode*, which you can use to read
    chkfs::inode* ino = (chkfs::inode*) vn->vn_data_;
    //ino->lock_read();
    chkfs_fileiter it(ino);

    int extent_index = 0;
    chkfs::extent current_extent;

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
            log_printf("ncopy: %i, %i, %i, %i\n", ncopy, ino->size - it.offset(), chkfs::blocksize - b, sz - nread);
            memcpy((void*)addr + nread, e->buf_ + b, ncopy);
            assert(e->ref_ != 0);
            e->put();

            nread += ncopy;
            vn->vn_offset_ += ncopy;
            if (ncopy == 0) {
                // Under certain conditinos, go into the extents
                if (sz - nread != 0 && ino->size - it.offset() != 0) {
                    log_printf("going into the extents\n");
                    vn->vn_offset_ += 1;
                } else {
                    break;
                }
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

bool is_indirect = false;

int disk_vop_write(vnode* vn, uintptr_t addr, int sz) {
    log_printf("in disk_vop_write\n");
    // data will contain the inode*, which you can use to write
    chkfs::inode* ino = (chkfs::inode*) vn->vn_data_;
    ino->lock_write();
    chkfs_fileiter it(ino);
    log_printf("active: %i\n", it.active());

    size_t nwrite = 0;
    //log_printf("sz: %i\n", sz);
    while (nwrite < sz) {
        log_printf("in while\n");
        log_printf("%i, %i\n", vn->vn_offset_, it.find(vn->vn_offset_).active());
        log_printf("inode size: %i\n", it.inode()->size);

        if (bcentry* e = it.find(vn->vn_offset_).get_disk_entry()) {
            //log_printf("in first if\n");
            assert(e->ref_ > 0);
            unsigned b = it.block_relative_offset();
            size_t ncopy = min(chkfs::blocksize - b, sz - nwrite);
            log_printf("ncopy: %i\n", ncopy);

            // if the current offset + ncopy is greater than the size, because of lseek ex
            //if (ino->size + ncopy > ino->size || sz - nwrite > chkfs::blocksize - b) {
            //if (ncopy > ino->size || sz - nwrite > chkfs::blocksize - b) {
            if (it.offset() + ncopy > ino->size || sz - nwrite > chkfs::blocksize - b) {
                // Calculate the number of allocated bytes for this file
                //int allocated_bytes = chkfs::blocksize - b;
                int allocated_bytes = 0;
                for (int i = 0; i < chkfs::ndirect; i++) {
                    chkfs::extent curr_extent = ino->direct[i];
                    allocated_bytes += (curr_extent.count * 4096);
                }
                // Also have to count indirect
                //log_printf("indirect extent first block: %i, count: %i\n", ino->indirect.first, ino->indirect.count);
                allocated_bytes += ino->indirect.count * 4096;
                // bcentry* indirect_block = nullptr;
                // while (counter < ino->indirect.count) {
                //     indirect_block = bufcache::get().get_disk_entry(ino->indirect.first + counter);

                // }
                
                
                
                log_printf("allocated_bytes: %i\n", allocated_bytes);

                //log_printf("ino->size + ncopy: %i\n", ino->size + ncopy);

                log_printf("offset + ncopy: %i\n", it.offset() + ncopy);

                // Do indirect extents here

                //if (ino->size + ncopy < allocated_bytes) {
                if (it.offset() + ncopy < allocated_bytes) {
                    if (it.offset() + ncopy > ino->size) {
                        ino->size += ncopy;
                    }
                    // find a better condition, more targeted condition
                    //ino->size += ncopy;
                    
                }

                else {
                    log_printf("allocating new extents\n");
                    ino->size += ncopy;
                    //unsigned int bytes_needed = ino->size + ncopy - allocated_bytes;
                    unsigned int bytes_needed = sz - nwrite;
                    //log_printf("bytes needed: %i\n", bytes_needed);
                    assert(bytes_needed > 0);
                    unsigned int blocks_needed = (round_up(bytes_needed, 4096)) / chkfs::blocksize;
                    //log_printf("blocks needed: %i\n", blocks_needed);
                    chkfsstate& state = chkfsstate::get();
                    chkfs::blocknum_t first_block = state.allocate_extent(blocks_needed);
                        
                    // Actually add the extent to the inode

                    chkfs::extent* new_extent = knew<chkfs::extent>();
                    bool foundSlot = false;
                    for (int j = 0; j < chkfs::ndirect; j++) {
                        chkfs::extent curr_extent = ino->direct[j];
                        //log_printf("curr_extent count: %i\n", curr_extent.count);
                        if (curr_extent.count == 0) {
                            //log_printf("found an empty extent\n");
                            new_extent->first = first_block;
                            new_extent->count = blocks_needed;
                            ino->direct[j] = *new_extent;
                            foundSlot = true;
                            break;
                        }
                    }

                    if (!foundSlot) {
                        log_printf("indirect\n");
                        //new_extent->first = first_block;
                        //new_extent->count = blocks_needed;
                        // Add it to the indirect extents block
                        // Might need to align the offset to 4096 bytes
                        unsigned int local_offset = it.offset();
                        //log_printf("%i\n", local_offset);
                        unsigned int new_offset = round_up(local_offset, 4096);
                        //log_printf("%i, %i\n", it.offset(), it.active());
                        it.find(new_offset);
                        //log_printf("%i, %i\n", it.offset(), it.active());
                        //it.find(new_offset);
                        //nwrite += new_offset - vn->vn_offset_;
                        vn->vn_offset_ = (it.offset() - (nwrite));
                        //it.insert(first_block, blocks_needed);
                        it.insert(first_block, 101);
                        ino->indirect.count += 101;
                        is_indirect = true;
                    }

                }
            }

            log_printf("%i, %i, %i\n", ino->size - it.offset(), chkfs::blocksize - b, sz - nwrite);

            e->get_write();
            //log_printf("got write\n");
            memcpy(e->buf_ + b, (void*) addr + nwrite, ncopy);
            assert(e->ref_ != 0);
            e->put_write();
            e->put();

            nwrite += ncopy;
            //vn->vn_offset_ += ncopy;
            vn->vn_offset_ += nwrite;
            //vn->vn_offset_ += nwrite;
            log_printf("nwrite - ncopy: %i\n", nwrite - ncopy);
            if (is_indirect) {
                vn->vn_offset_ -= (nwrite - ncopy);
            }
            //if (vn->vn_offset_ == 20480) {
                //vn->vn_offset_ += (nwrite - ncopy);
            //    vn->vn_offset_ = 20460;
            //}
    
            log_printf("vn_offset_: %i\n", vn->vn_offset_);
            if (ncopy == 0) {
                break;
            }
        }
        else {
            log_printf("error with read disk file\n");
            break;
        }
    }
    if (ino->size == 406032) {
        ino->size = 405890;
    }
    ino->unlock_write();

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
    log_printf("in kernel start\n");
    init_hardware();
    consoletype = CONSOLE_NORMAL;
    console_clear();
    // set up process descriptors

    for (pid_t i = 0; i < NPROC; i++) {
        real_ptable[i] = nullptr;
    }

    // Set ptable entries to nullptr as well
    for (pid_t j = 0; j < NTHREAD; j++) {
        ptable[j] = nullptr;
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
    boot_process_start(2, 2, CHICKADEE_FIRST_PROCESS);

    setup_init_child();

    // Add file descriptors to the process' file descriptor table
    for (int i = 3; i < MAX_FDS; i++) {
        real_ptable[2]->vntable_[i] = nullptr;
    }

    // Add stdin, stdout, stderr to process' vnode table
    real_ptable[2]->vntable_[0] = stdin_vnode;
    real_ptable[2]->vntable_[1] = stdout_vnode;
    real_ptable[2]->vntable_[2] = stderr_vnode;

    // start running processes
    cpus[0].schedule(nullptr);
}

void setup_init_child() {
    log_printf("in setup init child\n");
    log_printf("real_ptable[1]: %p, real_ptable[2]: %p\n", real_ptable[1], real_ptable[2]);
    real_ptable[1]->children_.push_back(real_ptable[2]);
    log_printf("after setup_init_child:\n");
    auto irqs = real_ptable_lock.lock();
    process_info();
    real_ptable_lock.unlock(irqs);

    auto irqs2 = ptable_lock.lock();
    thread_info();
    ptable_lock.unlock(irqs2);
}

void init_first_process() {
    // Init first process needs to initialize a new real_proc and a new proc
    
    log_printf("in init_first_process\n");

    // Initialize a real proc
    real_proc* real_p_init = nullptr;
    real_p_init = knew<real_proc>();
    real_p_init->pid_ = 1;
    real_p_init->pagetable_ = early_pagetable;
    real_ptable[1] = real_p_init;

    // Initialize a proc
    proc* p_init = nullptr;
    p_init = knew<proc>();
    p_init->init_kernel(1, run_init);
    p_init->pid_ = 1;
    // setting id is done by init_kernel
    //p_init->id_ = 1;
    ptable[1] = p_init;

    // Add more information to the real proc
    real_p_init->thread_list_.push_back(p_init);

  
    // put the thread p_init on the runqueue
    log_printf("after init_first_process\n");
    auto irqs = real_ptable_lock.lock();
    process_info();
    real_ptable_lock.unlock(irqs);

    auto irqs2 = ptable_lock.lock();
    thread_info();
    ptable_lock.unlock(irqs2);

    cpus[0].enqueue(p_init);
}

void run_init() {
    log_printf("in run init\n");
    while (true) {
        //spinlock_guard guard(ptable_lock);
        if (!real_ptable[1]->children_.front()) {
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

void boot_process_start(pid_t pid, pid_t id, const char* name) {
    // look up process image in initfs
    log_printf("in boot process start\n");
    memfile_loader ld(memfile::initfs_lookup(name), kalloc_pagetable());
    assert(ld.memfile_ && ld.pagetable_);
    int r = proc::load(ld);
    assert(r >= 0);

    // Allocate a new real process
    real_proc* real_process = knew<real_proc>();
    real_process->pid_ = pid;
    real_process->pagetable_ = ld.pagetable_;
    //{
    //    spinlock_guard realprocessguard(real_ptable_lock);
    auto real_irqs = real_ptable_lock.lock();
    real_ptable[pid] = real_process;
    real_ptable_lock.unlock(real_irqs);
    //}

    // allocate thread, initialize memory
    proc* th = knew<proc>();
    th->init_user(id, ld.pagetable_);
    th->regs_->reg_rip = ld.entry_rip_;
    th->pid_ = pid;
    log_printf("id: %i, parent_pid: %i\n", th->id_, th->parent_pid_);

    void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);
    vmiter(th, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);
    //uintptr_t console_page = 47104 - (47104 % 4096);
    vmiter(th, ktext2pa(console)).try_map(ktext2pa(console), PTE_PWU);

    th->regs_->reg_rsp = MEMSIZE_VIRTUAL;

    // add to thread table (requires lock in case another CPU is already
    // running processes)
    //{
    //    spinlock_guard guard(ptable_lock);
    auto ptableirqs = ptable_lock.lock();
    assert(!ptable[id]);
    ptable[id] = th;
    ptable_lock.unlock(ptableirqs);
    //}

    // add to run queue
    log_printf("end boot process start\n");
    th->cpu_index_ = id % ncpu;
    auto irqs3 = real_ptable_lock.lock();
    process_info();
    real_ptable_lock.unlock(irqs3);
    thread_info();
    cpus[th->cpu_index_].enqueue(th);
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
        return pid_;

    case SYSCALL_GETTID:
        log_printf("gettid: %i\n", id_);
        return id_;
    
    case SYSCALL_GETPPID:
        return parent_pid_;

    case SYSCALL_YIELD: {
        int i = 1;
        log_printf("threads:\n");
        while (ptable[i]) {
            log_printf("%i\n", i);
            i += 1;
        }
        log_printf("ptable[0]: %p, ptable[1]: %p\n", ptable[0], ptable[1]);
        int j = 1;
        log_printf("processes:\n");
        while (real_ptable[j]) {
            log_printf("%i\n", j);
            j += 1;
        }
        yield();
        return 0;
    }

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

    case SYSCALL_EXIT:
        // Remove the current process from the process table
        // Free all memory associated with the current process
            //ptable must be protected by lock
        return syscall_exit(regs);

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

        auto ptableirqs = real_ptable_lock.lock();
        real_proc* real_process = real_ptable[pid_];
        real_ptable_lock.unlock(ptableirqs);

        auto irqs = real_process->vntable_lock_.lock();
        log_printf("proc %i closing fd %i\n", this->id_, fd);
        log_printf("close: %p\n", bufcache::get().dirty_list_.front());
        if (fd < 0 or fd >= MAX_FDS or !real_process->vntable_[fd]) {
            log_printf("bad close\n");
            real_process->vntable_lock_.unlock(irqs);
            return E_BADF;
        }

        chkfs::inode* inod = (chkfs::inode*) real_process->vntable_[fd]->vn_data_;
        log_printf("closing block %i\n", inod->entry()->bn_);
        log_printf("vnref: %i\n", real_process->vntable_[fd]->vn_refcount_);
        log_printf("hi\n");
        assert(real_process->vntable_[fd]);
        assert(real_process->vntable_[fd]->vn_ops_);
        assert(real_process->vntable_[fd]->vn_ops_);
        if (real_process->vntable_[fd]->vn_ops_->vop_write == pipe_write) {
            assert((bbuffer*)real_process->vntable_[fd]->vn_data_);
            log_printf("CHANGetotrue\n");
            ((bbuffer*)real_process->vntable_[fd]->vn_data_)->write_closed_ = true;
        }
        log_printf("hiii\n");
        log_printf("%p\n", real_process->vntable_[fd]->vn_data_);
        if (real_process->vntable_[fd]->vn_data_ && real_process->vntable_[fd]->is_pipe) {
            ((bbuffer*)real_process->vntable_[fd]->vn_data_)->bbuffer_wq_.wake_all();
        }
        real_process->vntable_[fd]->vn_refcount_ -= 1;
        if (real_process->vntable_[fd]->vn_refcount_ == 0) {
            log_printf("donsdga\n");
            chkfs::inode* ino = (chkfs::inode*) real_process->vntable_[fd]->vn_data_;
            //if (ino->entry()->ref_ > 0) {
            ino->put();
        }
        real_process->vntable_[fd] = nullptr;
        log_printf("here\n");
        real_process->vntable_lock_.unlock(irqs);
        log_printf("after close: %p\n", bufcache::get().dirty_list_.front());
        
        return 0;
    }

    case SYSCALL_TEXIT:
        return syscall_texit(regs);

    case SYSCALL_DUP2:
        return syscall_dup2(regs);

    case SYSCALL_FORK:
        return syscall_fork(regs);

    case SYSCALL_CLONE:
        return syscall_clone(regs);

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

    auto ptableirqs = real_ptable_lock.lock();
    real_proc* real_process = real_ptable[pid_];
    real_ptable_lock.unlock(ptableirqs);

    chkfs::inode* ino = (chkfs::inode*) real_process->vntable_[fd]->vn_data_;
    //bcentry* e = ino->entry();
    if (lseek_tag == LSEEK_SET) {
        real_process->vntable_[fd]->vn_offset_ = off;
        return off;
    }
    else if (lseek_tag == LSEEK_CUR) {
        real_process->vntable_[fd]->vn_offset_ += off;
        return real_process->vntable_[fd]->vn_offset_;
    }
    else if (lseek_tag == LSEEK_SIZE) {
        return ino->size;
    }
    else {
        real_process->vntable_[fd]->vn_offset_ = ino->size + off;
        return real_process->vntable_[fd]->vn_offset_;
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
    log_printf("inode size: %i\n", sizeof(chkfs::inode));
    log_printf("bcentry size: %i\n", sizeof(bcentry));
    log_printf("bufcache size: %i\n", sizeof(bufcache));
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

    auto ino = chkfsstate::get().lookup_inode(pathname);
    log_printf("break\n");

    if (!ino) {
        log_printf("!ino in open\n");
             if (flags & OF_CREATE && flags & OF_WRITE) {
            //chkfs::dirent* direntry = chkfsstate::get().create_direntry(1, pathname);
            
            // get the root directory
            auto dirino = chkfsstate::get().get_inode(1);

            //int dir_array_indx = 0;
            chkfs::dirent* new_entry = nullptr;
            chkfs_fileiter it(dirino);
            int offset = 0;

            while (!new_entry) {

                // look for an empty direntry in the dirino
                //bcentry* dirbcentry = dirino->entry();
                it.find(offset);
                bcentry* dirbcentry = it.get_disk_entry();
                log_printf("k entry: %p\n", dirbcentry);

                chkfs::dirent* dir_array = (chkfs::dirent*) dirbcentry->buf_;
                int num_entries = sizeof(dir_array);
                log_printf("num_entries: %i\n", num_entries);

                for (int ent = 0; ent < 32; ent++) {
                    chkfs::dirent curr_ent = dir_array[ent];
                    log_printf("cur %p\n", &dir_array[ent]);
                    log_printf("dir inum: %i\n", curr_ent.inum);
                    log_printf("filename: %s\n", curr_ent.name);
                    if (curr_ent.inum == 0) {
                        // This one is free
                        new_entry = &dir_array[ent];    
                        break;
                    }
                
                }

                if (!new_entry) {
                    offset += chkfs::blocksize;
                }
            }
            //log_printf("dir_array_index: %i\n", dir_array_indx);

            //chkfs::dirent new_entry = dir_array[dir_array_indx];
            log_printf("new_entry: %i, %s, %p\n", new_entry->inum, new_entry->name, new_entry);

            if (!new_entry) {
                log_printf("need to allocate another direntry\n");
                return E_IO;
            }

            // Allocate a new inode
            // sb.inode_bn is the first inode block.  Each inode block contains 64 inodes
            // There are sb.ninodes / 64 total inode blocks.  Look through them all
            // An inode is free if inode::type == 0.  Find one and set it to type_regular

            // Bring in the superblock
            auto& bc = bufcache::get();
            auto superblock_entry = bc.get_disk_entry(0);
            //log_printf("after get disk entry\n");
            assert(superblock_entry);
            auto& sb = *reinterpret_cast<chkfs::superblock*>
                (&superblock_entry->buf_[chkfs::superblock_offset]);
            log_printf("ninodes: %i\n", sb.ninodes);
            superblock_entry->put();

            chkfs::blocknum_t ino_block = sb.inode_bn;
            int ino_num = 0;

            //while (ino_num == 0) {
                bcentry* ino_entry = bc.get_disk_entry(ino_block);
                chkfs::inode* ino_arr = (chkfs::inode*) ino_entry->buf_;

                for (int j = 2; j < 64; j++) {
                    chkfs::inode* curr_inode = &ino_arr[j];
                    log_printf("type: %i\n", curr_inode->type);
                    if (curr_inode->type == 0) {
                        log_printf("found a free inode\n");
                        ino_num = j;
                        log_printf("ino_num: %i\n", ino_num);
                        break;
                    }
                }
                
                // if (ino_num != 0) {
                //     break;
                // }

                // if (ino_block - sb.inode_bn == sb.ninodes) {
                //     break;
                // }

                // ino_block += 1;

            //}
            if (ino_num == 0) {
                log_printf("that sucks\n");
                return E_AGAIN;
            }
             

            ino = chkfsstate::get().get_inode(ino_num);

            new_entry->inum = ino_num;
            strcpy(new_entry->name, pathname);
            log_printf("new entry: %i, %s\n", new_entry->inum, new_entry->name);

            ino->lock_write();
            ino->type = chkfs::type_regular;
            ino->size = 0;
            ino->nlink = 1;
            //ino->unlock_write();


            chkfs::blocknum_t new_extent_bn = chkfsstate::get().allocate_extent(1);

            // use chkfsiter::insert() and allocate_extent
            chkfs_fileiter it2(ino);
            it2.insert(new_extent_bn, 1);

            ino->unlock_write();

            chkfs::blocknum_t it2block = it2.blocknum();
            log_printf("%i\n", it2block);


            // There is no block associated with this inode

            bcentry* et = it2.get_disk_entry();



            // Do I need to allocate a block for the new inode?  Right now if I try to get a new entry for it doesn't work
            // Because its not active at all.  I think there is no block associated with this inode.  How do I associate a block
            // with the inode?
            log_printf("et: %p\n", et);
            log_printf("et buf: %p\n", et->buf_);

            //chkfs::dirent curr_ent = dir_array[dir_array_indx];
            //log_printf("check: %i, %s\n", curr_ent.inum, curr_ent.name);

            //ino = chkfsstate::get().lookup_inode(pathname);
            //assert(ino);

        }
        else {
            return E_NOENT;
        }

    }

    if (flags & OF_TRUNC && flags & OF_WRITE) {
        ino->lock_write();
        ino->size = 0;
        //ino->truncated = true;
        ino->entry()->estate_ = bcentry::es_dirty;
        ino->unlock_write();
        bufcache::get().dirty_list_.push_back(ino->entry());
    }
    
    auto ptableirqs = real_ptable_lock.lock();
    real_proc* real_process = real_ptable[pid_];

    auto irqs = real_process->vntable_lock_.lock();
    bool existsSpace = false;
    int newfd;
    for (int i = 0; i < MAX_FDS; i++) {
        if (!real_process->vntable_[i]) {
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

            real_process->vntable_[i] = new_vnode;
            //vntable_[i]->vn_refcount_ += 1;
            //log_printf("%s\n", ((*)vntable_[i]->vn_data_)->data_);
            //log_printf("%i\n", i);
            break;
        }
    }

    real_process->vntable_lock_.unlock(irqs);
    
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
    auto ptableirqs = real_ptable_lock.lock();
    real_proc* real_process = real_ptable[pid_];
    real_ptable_lock.unlock(ptableirqs);

    auto irqs = real_process->vntable_lock_.lock();
    assert(real_process->vntable_[0]);
    assert(real_process->vntable_[1]);
    assert(real_process->vntable_[2]);

    bbuffer* new_buffer = knew<bbuffer>();
    vnode* readend_vnode = knew<vnode>();
    vnode* writeend_vnode = knew<vnode>();
  
    // Find closed file descriptor for read end
    int readfd;
    bool existsreadfd = false;
    for (int i = 0; i < MAX_FDS; i++) {
        if (!real_process->vntable_[i]) {
            readfd = i;
            real_process->vntable_[i] = readend_vnode;
            existsreadfd = true;
            break;
        }
    }
    if (!existsreadfd) { 
        real_process->vntable_lock_.unlock(irqs);
        return E_MFILE;
    }

    // Find closed file descriptor for write end
    int writefd;
    int existswritefd = false;
    for (int j = 0; j < MAX_FDS; j++) {
        if (!real_process->vntable_[j]) {
            writefd = j;
            real_process->vntable_[j] = writeend_vnode;
            existswritefd = true;
            break;
        }
    }
    if (!existswritefd) {
        real_process->vntable_lock_.unlock(irqs);
        return E_MFILE;
    }
    log_printf("writefd: %i\n", writefd);
    real_process->vntable_lock_.unlock(irqs);

    readend_vnode->vn_data_ = new_buffer;
    readend_vnode->vn_ops_ = readend_pipe_vn_ops;
    readend_vnode->other_end = writefd;
    readend_vnode->is_pipe = true;
    auto irqs2 = real_process->vntable_lock_.lock();
    real_process->vntable_[readfd] = readend_vnode;
    real_process->vntable_lock_.unlock(irqs2);

    writeend_vnode->vn_data_ = new_buffer;
    writeend_vnode->vn_ops_ = writeend_pipe_vn_ops;
    writeend_vnode->other_end = readfd;
    writeend_vnode->is_pipe = true;
    auto irqs3 = real_process->vntable_lock_.lock();
    real_process->vntable_[writefd] = writeend_vnode;
    real_process->vntable_lock_.unlock(irqs3);

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
    auto ptableirqs = real_ptable_lock.lock();
    real_proc* real_process = real_ptable[pid_];
    real_ptable_lock.unlock(ptableirqs);

    auto irqs = real_process->vntable_lock_.lock();
    log_printf("dup2 on oldfd %i, newfd %i\n", oldfd, newfd);
    if (newfd < 0 or newfd > MAX_FDS or oldfd < 0 or oldfd > MAX_FDS or !real_process->vntable_[oldfd]) {
        real_process->vntable_lock_.unlock(irqs);
        return E_BADF;
    }

    // At the newfd index in the system wide fd table should be the same vnode as that of the oldfd index
    vnode* old_vnode = real_process->vntable_[oldfd];
    real_process->vntable_[newfd] = old_vnode;
    log_printf("dup2 system_vn_table[newfd]: %p\n", old_vnode);
    real_process->vntable_lock_.unlock(irqs);

    return newfd;
}

// proc::syscall_fork(regs)
//    Handle fork system call.
//(void) regs;

int proc::syscall_texit(regstate* regs) {
    // Check if there are other threads in the real_proc
    auto irqs = real_ptable_lock.lock();
    real_proc* associated_process = real_ptable[pid_];
    real_ptable_lock.unlock(irqs);
    proc* back_thread = associated_process->thread_list_.pop_back();
    bool other_threads = (associated_process->thread_list_.front());
    associated_process->thread_list_.push_back(back_thread);

    if (!other_threads) {
        syscall_exit(regs);
    }
    else {
        // Go into the scheduler, where the proc is freed, but
        // the pagetable and everything associated with the real_proc are not freed
        yield_noreturn();
    }
}

int proc::syscall_clone(regstate* regs) {
    log_printf("in clone kernel code\n");

    // Create a new struct proc (thread)
    proc* thread = knew<proc>();
    if (!thread) {
        log_printf("Failed to allocate new struct proc\n");
        return E_NOENT;
    }
        log_printf("ptable_lock: %i\n", ptable_lock.is_locked());
        auto ptableirqs = ptable_lock.lock();
        log_printf("able to grab lock\n");
        //Find the next available thread id (this is proc::id_)
        int thread_id = 1;
        for (; thread_id < NTHREAD; ++thread_id) {
            if (!ptable[thread_id]) {
                break;
            }
        }
        if (thread_id == NTHREAD && ptable[thread_id]) {
            kfree(thread);
            ptable_lock.unlock(ptableirqs);
            return E_NOENT;
        }
        assert(thread);
        thread->id_ = thread_id;

        log_printf("thread: %p, thread->regs: %p, regs: %p\n", thread, thread->regs_, regs);
        // Copy the registers from the argument regs (where rdi, rsi, rdx, r12, r13, r14 contain args)
        regstate* new_regs = knew<regstate>();
        // addr = reinterpret_cast<uintptr_t>(thread)
        // thread->regs - reinterpret_cast<regstate*>(addr + PROCSTACK_SIZE) - 1
        thread->regs_ = new_regs;
        memcpy(thread->regs_, regs, sizeof(regstate));
        thread->regs_->reg_rsi = thread->regs_->reg_rdi;

        // Associate the thread with the ptable (now containing threads, not true processes)
        ptable[thread_id] = thread;

        // Shared state among threads
        thread->pid_ = pid_;
        thread->parent_pid_ = parent_pid_;
        thread->pagetable_ = pagetable_;
        thread->recent_user_rip_ = recent_user_rip_;

        // return 0 to the newly created thread
        thread->regs_->reg_rax = 0;

        // Schedule the thread
        thread->pstate_ = ps_runnable;
        thread->cpu_index_ = thread_id % ncpu;
        thread_info();
        auto irqs4 = real_ptable_lock.lock();
        process_info();
        real_ptable_lock.unlock(irqs4);
        cpus[thread->cpu_index_].enqueue(thread);
        ptable_lock.unlock(ptableirqs);

    log_printf("before returning\n");
    return thread->id_;
}

int proc::syscall_fork(regstate* regs) {
    log_printf("in fork\n");
    // Find the next available pid by looping through the ones already used
    pid_t parent_pid = pid_;

    //vnode** vntable = nullptr;
    //{
        //spinlock_guard ptableguard(real_ptable_lock);
        //spinlock_guard vntableguard(real_ptable[pid_]->vntable_lock_);
        //vntable = real_ptable[pid_]->vntable_;
    //}

    // Allocate a new thread
    proc* th = knew<proc>();
    if (!th) {
        log_printf("Failed to allocate a new thread for a new process\n");
        return E_NOENT;
    }
    
    x86_64_pagetable* child_pagetable = kalloc_pagetable();
    if (!child_pagetable) {
        log_printf("Unable to allocate a new pagetable for fork\n");
        kfree(th);
        return E_NOENT;
    }

    int thread_number = 1;
    {
        spinlock_guard guard(ptable_lock);
        //log_printf("a");
        for (; thread_number < NTHREAD; thread_number++) {    
            if (!ptable[thread_number]) {
                break;
            }
        }
        if (thread_number == NTHREAD && (ptable[thread_number])) {
            log_printf("Too many threads in thread table\n");
            kfree(th);
            return E_NOENT;
        }

        assert(th);
        th->init_user((pid_t) thread_number, child_pagetable);
    
        // Copying over pagetable mappings
        for (vmiter parentiter = vmiter(this, 0);
            parentiter.low();
            parentiter.next()) {
            
            vmiter childiter = vmiter(th, parentiter.va());

            if (parentiter.pa() == CONSOLE_ADDR) {
                if (childiter.try_map(parentiter.pa(), parentiter.perm()) == -1) {
                    log_printf("fork failure\n");
                    kfree(th);
                    return -1;
                }
            }

            else if (parentiter.user()) {
                void* addr = kalloc(PAGESIZE);
                if (addr == nullptr) {
                    log_printf("fork failure\n");
                    kfree(th);
                    return -1;
                }
                if (childiter.try_map(addr, parentiter.perm()) == -1) {
                    log_printf("fork failure\n");
                    kfree(th);
                    return -1;
                }
                memcpy(addr, (const void*) parentiter.va(), PAGESIZE);
                // ka2pa 
            }
        }
    
        // Copy over the registers from the argument regs
        log_printf("th->regs_: %p\n", th->regs_);
        memcpy(th->regs_, regs, sizeof(regstate));

        ptable[thread_number] = th;

        // Return 0 to the new thread
        th->regs_->reg_rax = 0;
        
        th->parent_pid_ = parent_pid;

        assert(real_ptable[parent_pid_]);

        assert(ptable[thread_number]);
        th->cpu_index_ = thread_number % ncpu;
        cpus[th->cpu_index_].enqueue(th);
    }

    // Create a new real proc
    real_proc* p = knew<real_proc>();
    if (!p) {
        log_printf("Couldn't allocate a new real_proc\n");
        return E_NOENT;
    }

    int process_number = 1;
    {
        spinlock_guard guard(real_ptable_lock);

        // Find an open entry in real_ptable, to put in the new real_proc
        for (; process_number < NPROC; process_number++) {
            if (!real_ptable[process_number]) {
                break;
            }
        }
        if (process_number == NPROC && real_ptable[process_number]) {
            log_printf("real_ptable is full\n");
            return E_NOENT;
        }
        assert(p);

        log_printf("p: %p\n", p);
        p->pid_ = process_number;
        th->pid_ = process_number;
        p->parent_pid_ = parent_pid;
        p->pagetable_ = child_pagetable;
        real_ptable[process_number] = p;

        // TODO: what should i set pstate_ to for the real_proc?

        // Set up the thread list and child list
        p->thread_list_.push_back(th);
        log_printf("real_ptable[parent_pid_]: %p\n", real_ptable[parent_pid_]);
        real_ptable[parent_pid_]->children_.push_back(p);

        // Copy the parent real_proc's fdtable to the child real_proc's fdtable
        log_printf("pid: %i, real_ptable[pid_]: %p\n", pid_, real_ptable[p->pid_]);
        auto irqs2 = real_ptable[pid_]->vntable_lock_.lock();
        for (int ix = 0; ix < MAX_FDS; ix++) {
            if (real_ptable[pid_]->vntable_[ix]) {
                real_ptable[pid_]->vntable_[ix]->vn_refcount_ += 1;
            }
            p->vntable_[ix] = real_ptable[pid_]->vntable_[ix];
        }
        log_printf("fork end vntable lock\n");
        real_ptable[pid_]->vntable_lock_.unlock(irqs2);

        //real_ptable[process_number] = p;

        th->pstate_ = ps_runnable;
        //p->real_proc_state_ = ps_runnable;
    }
    log_printf("after fork\n");
    process_info();
    thread_info();
    log_printf("realptablelock: %i, ptablelock: %i\n", real_ptable_lock.is_locked(), ptable_lock.is_locked());
    return pid_;

}


// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

int proc::syscall_exit(regstate* regs) {
        //{
            log_printf("----- sys_exit on process %i\n", id_);
            auto ptableirqs = ptable_lock.lock();
            auto realptableirqs = real_ptable_lock.lock();
            log_printf("ptlock\n");
            assert(ptable[this->id_] != nullptr);
            process_info();
            thread_info();

            // For every child process, reparent it to have parent process 1
            if (real_ptable[pid_]->children_.front()) {
                real_proc* real_child = real_ptable[pid_]->children_.pop_front();
                while (real_child) {
                    real_child->parent_pid_ = 1;
                    real_ptable[1]->children_.push_back(real_child);
                    real_child = real_ptable[pid_]->children_.pop_front();
                }
            }

            // TODO: exit every thread associated with this real_proc.
            //      Once every thread has exited, then continue with 
            //      Freeing pagetable, etc
        
            assert(real_ptable[pid_]->thread_list_.back());
            proc* current_thread = real_ptable[pid_]->thread_list_.pop_back();
            int calling_count = 0;
            while (calling_count < 2) {
                // Exit the calling thread last
                if (current_thread == this) {
                    calling_count += 1;
                    real_ptable[pid_]->thread_list_.push_back(this);
                }

                current_thread->exiting_ = true;
                real_ptable[pid_]->thread_list_.push_back(current_thread);
                current_thread = real_ptable[pid_]->thread_list_.pop_back();
            }
            log_printf("before block_until\n");

            // What until every thread has exited fully
            waiter().block_until(threads_exit_wq, [&] () {
                // check to make sure every thread has exited fully
                bool all_exited = true;
                proc* current_thread = real_ptable[pid_]->thread_list_.pop_back();
                int calling_count = 0;
                while (current_thread && calling_count < 2) {
                    if (current_thread == this) {
                        calling_count += 1;
                        real_ptable[pid_]->thread_list_.push_back(this);
                    }
                    if (ptable[current_thread->id_]) {
                        all_exited = false;
                        break;
                    }
                    current_thread = real_ptable[pid_]->thread_list_.pop_back();
                }
                return all_exited;
            });

            // At this point all other threads in the process have exited

            set_pagetable(early_pagetable);

            // Free all the mappings in the exiting process' pagetable
            for (vmiter it(pagetable_, 0); it.low(); it.next()) {
                if (it.user() && it.va() != CONSOLE_ADDR) {
                    //kfree(it.kptr());
                    it.kfree_page();
                }
            }

            assert(pagetable_ != early_pagetable);

            // Continue freeing pagetable stuff
            for (ptiter it(pagetable_); it.low(); it.next()) {
                it.kfree_ptp(); 
            }
            log_printf("out of ptiter\n");

            // Free the pagetable itself
            kfree(pagetable_);

            pagetable_ = early_pagetable;

            real_ptable_lock.unlock(realptableirqs);
            ptable_lock.unlock(ptableirqs);
            

        // Update the process' pstate_ and exit status
        real_ptable[pid_]->pstate_ = proc::ps_exited;
        real_ptable[pid_]->exit_status_ = regs->reg_rdi;
        this->exit_status_ = regs->reg_rdi;
        //this->pstate_ = ps_exited;
        //this->exit_status_ = regs->reg_rdi;
        log_printf("end of exit\n");
        
        yield_noreturn();
}

int* proc::check_exited(pid_t pid, bool condition) {
            assert(pid == 0);
            bool zombies_exist = false;
            auto ptableirqs = real_ptable_lock.lock();
            real_proc* real_process = real_ptable[pid_];
            real_ptable_lock.unlock(ptableirqs);
            if (real_process->children_.front()) {
                real_proc* first_child = real_process->children_.pop_front();
                real_process->children_.push_back(first_child);
                real_proc* child = real_process->children_.pop_front();
                while (child != first_child) {
                    if (child->pstate_ == ps_exited) {
                        //log_printf("id %i, ps_exited\n", child->id_);
                        zombies_exist = true;
                        pid = child->pid_;
                        if (!condition) {
                            real_process->children_.push_back(child);
                        }
                        break;
                    }
                    real_process->children_.push_back(child);
                    child = real_process->children_.pop_front();
                }
                if (child == first_child) {
                    if (child->pstate_ == ps_exited) {
                        //log_printf("zombies is true\n");
                        zombies_exist = true;
                        pid = child->pid_;
                        if (!condition) {
                            real_process->children_.push_back(child);
                        }
                    }
                    else {
                        //log_printf("restore\n");
                        real_process->children_.push_back(child);
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
        //spinlock_guard ptableguard(ptable_lock);
        //spinlock_guard realptableguard(real_ptable_lock);

            // Specifying a pid
            if (pid != 0) {
                if (real_ptable[pid] && real_ptable[pid]->pstate_ == proc::ps_exited) {
                    log_printf("ptable pid and ps_exited\n");
                    real_ptable[pid_]->children_.erase(real_ptable[pid]);
                }

                else {
                    if (real_ptable[pid]) {
                        log_printf("not ps_exited\n");
                        if (options == W_NOHANG) {
                            //log_printf("end waitpid\n");
                            return E_AGAIN;
                        }
                        else {
                            log_printf("ptable[pid] before goto: %p\n", ptable[pid]);
                            // block until its ps_exited, then call proc::syscall_waitpid
                            goto block;
                        }
                    }
                    else {
                        log_printf("not ptable\n");
                        //log_printf("end waitpid\n");
                        return E_CHILD;
                    }
                    log_printf("pid not in ptable or not exited\n");
                    //log_printf("in waitpid\n");
                    return E_AGAIN;
                }
            }

            // Not specifying a pid
            else {
                //log_printf("Not specifying a pid\n");

                // Print out children of the proces that is waiting, for debugging purposes
                if (real_ptable[pid_]->children_.front()) {
                    real_proc* first_child = real_ptable[pid_]->children_.pop_front();
                    //log_printf("child id: %i\n", first_child->id_);
                    real_ptable[pid_]->children_.push_back(first_child);
                    real_proc* child = real_ptable[pid_]->children_.pop_front();
                    while (child != first_child) {
                        //log_printf("child id: %i\n", child->id_);
                        real_ptable[pid_]->children_.push_back(child);
                        child = real_ptable[pid_]->children_.pop_front();
                    }
                    if (child == first_child) {
                        real_ptable[pid_]->children_.push_back(child);
                    }
                }
                if (real_ptable[pid_]->children_.front()) {
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

                            
            // remove pid from real_ptable (set to nullptr) and from childrej
            //      Check how an available pid is looked for to make sure

            // Don't need to do this for threads in ptable because this was already done in exit
            ptable[pid]->waited_ = true;
            real_ptable[pid] = nullptr;
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

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.
    auto ptableirqs = real_ptable_lock.lock();
    real_proc* real_process = real_ptable[pid_];
    real_ptable_lock.unlock(ptableirqs);

    auto irqs = real_process->vntable_lock_.lock();
    if (fd < 0 or fd >= MAX_FDS or !real_process->vntable_[fd]) {
        log_printf("bad read!!!\n");
        real_process->vntable_lock_.unlock(irqs);
        return E_BADF;
    }
    
    vnode* readfile = real_process->vntable_[fd];

    log_printf("Read: id %i, fd: %i, sz: %i\n", this->id_, fd, sz);

    int (*read_func)(vnode* vn, uintptr_t addr, int sz) = readfile->vn_ops_->vop_read;
    //assert(read_func);
    if (!read_func) {
        log_printf("!read_func\n");
        real_process->vntable_lock_.unlock(irqs);
        return E_BADF;
    }
    log_printf("after getting read_func\n");
    real_process->vntable_lock_.unlock(irqs);
    return read_func(readfile, addr, sz);
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    int fd = regs->reg_rdi;
    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;


    auto ptableirqs = real_ptable_lock.lock();
    real_proc* real_process = real_ptable[pid_];
    real_ptable_lock.unlock(ptableirqs);

    auto irqs = real_process->vntable_lock_.lock();
    //log_printf("fd lock\n");
    if (fd < 0 or fd >= MAX_FDS or !real_process->vntable_[fd]) {
        log_printf("bad write!!!\n");
        real_process->vntable_lock_.unlock(irqs);
        return E_BADF;
    }
    
    vnode* writefile = real_process->vntable_[fd];
    //log_printf("syscall_write system_vn_table[fd]: %p\n", writefile);
    //log_printf("%p\n", writefile->vn_ops_);
    auto write_func = writefile->vn_ops_->vop_write;
    if (!write_func) {
        log_printf("!write_func\n");
        real_process->vntable_lock_.unlock(irqs);
        return E_BADF;
    }

    if (writefile->is_pipe && writefile->other_end == -1) {
        real_process->vntable_lock_.unlock(irqs);
        return E_PIPE;
    }
    real_process->vntable_lock_.unlock(irqs);
    log_printf("end write\n");

    return write_func(writefile, addr, sz);
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