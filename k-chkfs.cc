#include "k-chkfs.hh"
#include "k-ahci.hh"
#include "k-chkfsiter.hh"

bufcache bufcache::bc;

bufcache::bufcache() {
}


// bufcache::get_disk_entry(bn, cleaner)
//    Reads disk block `bn` into the buffer cache, obtains a reference to it,
//    and returns a pointer to its bcentry. The returned bcentry has
//    `buf_ != nullptr` and `estate_ >= es_clean`. The function may block.
//
//    If this function reads the disk block from disk, and `cleaner != nullptr`,
//    then `cleaner` is called on the entry to clean the block data.
//
//    Returns `nullptr` if there's no room for the block.

bcentry* bufcache::get_disk_entry(chkfs::blocknum_t bn,
                                  bcentry_clean_function cleaner) {
    log_printf("in get disk entry front: %p\n", dirty_list_.front());                                 
    assert(chkfs::blocksize == PAGESIZE);
    auto irqs = lock_.lock();

    // look for slot containing `bn`
    size_t i, empty_slot = -1;
    for (i = 0; i != ne; ++i) {
        if (e_[i].empty()) {
            if (empty_slot == size_t(-1)) {
                empty_slot = i;
            }
        } else if (e_[i].bn_ == bn) {
            break;
        }
    }

    // if not found, use free slot
    if (i == ne) {
        if (empty_slot == size_t(-1)) {
            // cache full!
            lock_.unlock(irqs);
            log_printf("bufcache: no room for block %u\n", bn);
            return nullptr;
        }
        i = empty_slot;
    }

    // obtain entry lock
    e_[i].lock_.lock_noirq();

    // mark allocated if empty
    if (e_[i].empty()) {
        e_[i].estate_ = bcentry::es_allocated;
        e_[i].bn_ = bn;
    }

    // no longer need cache lock
    lock_.unlock_noirq();

    // mark reference
    log_printf("gde %i incr\n", e_[i].bn_);
    ++e_[i].ref_;
    if (e_[i].link_.is_linked() && e_[i].estate_ != bcentry::es_dirty) {
        lru_queue_.erase(&e_[i]);
    }
    

    // load block
    bool ok = e_[i].load(irqs, cleaner);

    // unlock and return entry
    if (!ok) {
        log_printf("in gt disk entry, %i about to dec refcount\n", e_[i].bn_);
        --e_[i].ref_;
    }
    e_[i].lock_.unlock(irqs);
    log_printf("end disk entry, front: %p\n", dirty_list_.front());
    return ok ? &e_[i] : nullptr;
}


// bcentry::load(irqs, cleaner)
//    Completes the loading process for a block. Requires that `lock_` is
//    locked, that `estate_ >= es_allocated`, and that `bn_` is set to the
//    desired block number.

bool bcentry::load(irqstate& irqs, bcentry_clean_function cleaner) {
    bufcache& bc = bufcache::get();
    //log_printf("in load\n");

    // load block, or wait for concurrent reader to load it
    while (true) {
        assert(estate_ != es_empty);
        if (estate_ == es_allocated) {
            //log_printf("es_allocated\n");
            if (!buf_) {
                log_printf("!buf\n");
                buf_ = reinterpret_cast<unsigned char*>
                    (kalloc(chkfs::blocksize));
                if (!buf_) {
                    log_printf("again !buf\n");
                    return false;
                }
            }
            estate_ = es_loading;
            lock_.unlock(irqs);
            //log_printf("buf_ = %p\n", buf_);
            //log_printf("about to read sata disk\n");
            sata_disk->read(buf_, chkfs::blocksize,
                            bn_ * chkfs::blocksize);

            //log_printf("finished reading sata disk\n");
            irqs = lock_.lock();
            estate_ = es_clean;
            if (cleaner) {
                //log_printf("cleaning up\n");
                cleaner(this);
            }
            //log_printf("about to bc wakeall\n");
            bc.read_wq_.wake_all();
        } else if (estate_ == es_loading) {
            //log_printf("es_loading\n");
            waiter().block_until(bc.read_wq_, [&] () {
                    return estate_ != es_loading;
                }, lock_, irqs);
        } else {
            //log_printf("something else\n");
            return true;
        }
    }
}


// bcentry::put()
//    Releases a reference to this buffer cache entry. The caller must
//    not use the entry after this call.

void bcentry::put() {
    spinlock_guard guard(lock_);
    assert(ref_ != 0);
    // eviction here.  Implement LRU
    // Strategy:  Assign a recent number to each bcentry.  When put is called:
    //  Assign the current bcentry's recent number to 1.  Increment all other
    //  Recent numbers in the bufcache.  While iterating, maintain a maximum var
    //  for bcentry with ref = 0.  Clear the bcentry associated with the maximum var
    //
    // Synchronization:
    //  If put is holding the buffercache wide lock, we are all good.  Otherwise, problems
    //  Have a queue, using list_links thing
    
    // if (--ref_ == 0) {
    //     log_printf("clearing\n");
    //     clear();
    // }
    log_printf("in bcentry::put, bn %i, about to decr refcount\n", bn_);
    --ref_;
    auto& bc = bufcache::get();
    //log_printf("gooo\n");

    if (ref_ == 0) {
        //log_printf("%p\n", bc.lru_queue_.prev(this));
        //log_printf("%p\n", bc.lru_queue_.next(this));
        if (!link_.is_linked() && estate_ != es_dirty) {
            log_printf("add to lru %i\n", bn_);
            bc.lru_queue_.push_back(this);
        }
    }
    //log_printf("b\n");

    auto irqs = bc.lock_.lock();

    bool is_full = true;
    for (int i = 0; i < bc.ne; i++) {
        if (bc.e_[i].empty()) {
            is_full = false;
            break;
        }
    }
    if (is_full) {
        log_printf("is full\n");
        assert(bc.lru_queue_.front());
        log_printf("z\n");
        bcentry* last_entry = bc.lru_queue_.pop_front();
        log_printf("clearing %i\n", last_entry->bn_);
        last_entry->clear();
    }

    bc.lock_.unlock(irqs);
}


// bcentry::get_write()
//    Obtains a write reference for this entry.

void bcentry::get_write() {
    waiter().block_until(write_wq_, [&] () {
        return write_ref_ == 0;      
    });

    write_ref_ += 1;

    estate_ = bcentry::es_dirty;
    if (link_.is_linked()) {
        bufcache::get().lru_queue_.erase(this);
    }
    log_printf("adding bn %i\n", bn_);
    //if (e->link_.is_linked()) {
    //bufcache::get().lru_queue_.erase(e);
    log_printf("bufcache add: %p\n", &bufcache::get());
    bufcache::get().dirty_list_.push_back(this);
    log_printf("front: %p, %p\n", bufcache::get().dirty_list_.front(), &bufcache::get().dirty_list_);
    //}
    assert(write_ref_ == 1);

}


// bcentry::put_write()
//    Releases a write reference for this entry.

void bcentry::put_write() {
    write_ref_ -= 1;
    write_wq_.wake_all();

}


// bufcache::sync(drop)
//    Writes all dirty buffers to disk, blocking until complete.
//    If `drop > 0`, then additionally free all buffer cache contents,
//    except referenced blocks. If `drop > 1`, then assert that all inode
//    and data blocks are unreferenced.

int bufcache::sync(int drop) {
    log_printf("in sync\n");
    log_printf("sync bufcache: %p, %p\n", this, &this->dirty_list_);
    // write dirty buffers to disk
    // Your code here!
    log_printf("front top sync: %p\n", dirty_list_.front());
    list<bcentry, &bcentry::link_> mydirty;
    mydirty.swap(dirty_list_);
    log_printf("is buffercache locked? %i\n", lock_.is_locked());
    log_printf("front: %p\n", mydirty.front());
    while (bcentry* e = mydirty.pop_front()) {
        // get write reference by calling bcentry::get_write()
        //auto irqs = lock_.lock();
        e->get_write();

        // write bcentry to disk
        //  Probably some kind of call to ahcistate::read_or_write()
        //auto irqs2 = e->lock_.lock();
        log_printf("before write: block %i, ref %i\n", e->bn_, e->ref_);
        sata_disk->write(e->buf_, chkfs::blocksize, e->bn_ * chkfs::blocksize);
        
        // set state to clean
        e->estate_ = bcentry::es_clean;
        //lock_.unlock(irqs);
       // e->lock_.unlock(irqs2);

        // put write reference
        //lock_.unlock(irqs);
        e->put_write();


    }

    // drop clean buffers if requested
    if (drop > 0) {
        spinlock_guard guard(lock_);
        for (size_t i = 0; i != ne; ++i) {
            spinlock_guard eguard(e_[i].lock_);
            log_printf("eiref: %i, bn %i\n", e_[i].ref_, e_[i].bn_);

            // validity checks: referenced entries aren't empty; if drop > 1,
            // no data blocks are referenced
            assert(e_[i].ref_ == 0 || e_[i].estate_ != bcentry::es_empty);
            if (e_[i].ref_ > 0 && drop > 1 && e_[i].bn_ >= 2) {
                error_printf(CPOS(22, 0), COLOR_ERROR, "sync(2): block %u has nonzero reference count\n", e_[i].bn_);
                assert_fail(__FILE__, __LINE__, "e_[i].bn_ < 2");
            }

            // actually drop buffer
            if (e_[i].ref_ == 0) {
                e_[i].clear();
            }
        }
    }

    return 0;
}


// inode lock functions
//    The inode lock protects the inode's size and data references.
//    It is a read/write lock; multiple readers can hold the lock
//    simultaneously.
//
//    IMPORTANT INVARIANT: If a kernel task has an inode lock, it
//    must also hold a reference to the disk page containing that
//    inode.

namespace chkfs {

void inode::lock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    while (true) {
        if (v >= mlock_t(-2)) {
            current()->yield();
            v = mlock.load(std::memory_order_relaxed);
        } else if (mlock.compare_exchange_weak(v, v + 1,
                                               std::memory_order_acquire)) {
            return;
        } else {
            // `compare_exchange_weak` already reloaded `v`
            pause();
        }
    }
}

void inode::unlock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    assert(v != 0 && v != mlock_t(-1));
    while (!mlock.compare_exchange_weak(v, v - 1,
                                        std::memory_order_release)) {
        pause();
    }
}

void inode::lock_write() {
    mlock_t v = 0;
    while (!mlock.compare_exchange_weak(v, mlock_t(-1),
                                        std::memory_order_acquire)) {
        current()->yield();
        v = 0;
    }
}

void inode::unlock_write() {
    assert(has_write_lock());
    mlock.store(0, std::memory_order_release);
}

bool inode::has_write_lock() const {
    return mlock.load(std::memory_order_relaxed) == mlock_t(-1);
}

}


// chickadeefs state

chkfsstate chkfsstate::fs;

chkfsstate::chkfsstate() {
}


// clean_inode_block(entry)
//    Called when loading an inode block into the buffer cache. It clears
//    values that are only used in memory.

static void clean_inode_block(bcentry* entry) {
    //log_printf("clean inode_block\n");
    uint32_t entry_index = entry->index();
    auto is = reinterpret_cast<chkfs::inode*>(entry->buf_);
    for (unsigned i = 0; i != chkfs::inodesperblock; ++i) {
        // inode is initially unlocked
        is[i].mlock = 0;
        // containing entry's buffer cache position is `entry_index`
        is[i].mbcindex = entry_index;
    }
}


// chkfsstate::get_inode(inum)
//    Returns inode number `inum`, or `nullptr` if there's no such inode.
//    Obtains a reference on the buffer cache block containing the inode;
//    you should eventually release this reference by calling `ino->put()`.

chkfs::inode* chkfsstate::get_inode(inum_t inum) {
    //log_printf("in get inode\n");
    auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    //log_printf("after get disk entry\n");
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    //log_printf("%i\n", sb.ninodes);
    superblock_entry->put();

    chkfs::inode* ino = nullptr;
    //log_printf("inum: %i, sb.ninodes: %i\n", inum, sb.ninodes);
    if (inum > 0 && inum < sb.ninodes) {
        //log_printf("1c\n");
        auto bn = sb.inode_bn + inum / chkfs::inodesperblock;
        if (auto inode_entry = bc.get_disk_entry(bn, clean_inode_block)) {
            //log_printf("2c\n");
            ino = reinterpret_cast<inode*>(inode_entry->buf_);
        }
    }
    if (ino != nullptr) {
        ino += inum % chkfs::inodesperblock;
    }
    return ino;
}


namespace chkfs {
// chkfs::inode::entry()
//    Returns a pointer to the buffer cache entry containing this inode.
//    Requires that this inode is a pointer into buffer cache data.
bcentry* inode::entry() {
    assert(mbcindex < bufcache::ne);
    auto entry = &bufcache::get().e_[mbcindex];
    assert(entry->contains(this));
    return entry;
}

// chkfs::inode::put()
//    Releases the caller’s reference to this inode, which must be located
//    in the buffer cache.
void inode::put() {
    entry()->put();
}
}


// chkfsstate::lookup_inode(dirino, filename)
//    Looks up `filename` in the directory inode `dirino`, returning the
//    corresponding inode (or nullptr if not found). The caller must have
//    a read lock on `dirino`. The returned inode has a reference that
//    the caller should eventually release with `ino->put()`.

chkfs::inode* chkfsstate::lookup_inode(inode* dirino,
                                       const char* filename) {
    chkfs_fileiter it(dirino);

    // read directory to find file inode
    chkfs::inum_t in = 0;
    for (size_t diroff = 0; !in; diroff += blocksize) {
        if (bcentry* e = it.find(diroff).get_disk_entry()) {
            size_t bsz = min(dirino->size - diroff, blocksize);
            auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
            for (unsigned i = 0; i * sizeof(*dirent) < bsz; ++i, ++dirent) {
                if (dirent->inum && strcmp(dirent->name, filename) == 0) {
                    in = dirent->inum;
                    break;
                }
            }
            e->put();
        } else {
            return nullptr;
        }
    }
    return get_inode(in);
}


// chkfsstate::lookup_inode(filename)
//    Looks up `filename` in the root directory.

chkfs::inode* chkfsstate::lookup_inode(const char* filename) {
    auto dirino = get_inode(1);
    //log_printf("get inode %p\n", dirino);
    if (dirino) {
        dirino->lock_read();
        auto ino = fs.lookup_inode(dirino, filename);
        dirino->unlock_read();
        dirino->put();
        return ino;
    } else {
        return nullptr;
    }
}


// chkfsstate::allocate_extent(unsigned count)
//    Allocates and returns the first block number of a fresh extent.
//    The returned extent doesn't need to be initialized (but it should not be
//    in flight to the disk or part of any incomplete journal transaction).
//    Returns the block number of the first block in the extent, or an error
//    code on failure. Errors can be distinguished by
//    `blocknum >= blocknum_t(E_MINERROR)`.

auto chkfsstate::allocate_extent(unsigned count) -> blocknum_t {
    // Your code here

    // Search for count number of free blocks in the free block bitmap
    //      Use bitset view on the address of first bitmap block (fbb->buf)
    // Then set those free blocks to be not free in the bitmap
    // Then return the first block in the extent

    auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    //log_printf("after get disk entry\n");
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    //log_printf("%i\n", sb.ninodes);
    superblock_entry->put();

    // Get address of first free block in fbb
    chkfs::blocknum_t first_fbb = sb.fbb_bn;
    bcentry* e = bc.get_disk_entry(sb.fbb_bn);
    assert(e);
    void* fbb_addr = e->buf_;
    e->put();

    // Use bitset_view
    bitset_view fbb_view(reinterpret_cast<uint64_t*>(fbb_addr), chkfs::bitsperblock);
    int counter = 0;
    int startblock = 0;
    for (int endblock = 0; endblock < chkfs::bitsperblock; endblock++) {
        if (fbb_view[endblock] == 1) {
            counter += 1;
        }
        else {
            startblock = endblock;
            counter = 0;
        }

        if (counter == count) {
            for (int block = startblock; block < endblock; block++) {
                fbb_view[block] = false;
                bcentry* current_entry = bc.get_disk_entry(block);
                //current_entry->get_write();
                // current_entry->estate_ = bcentry::es_dirty;
                // bc.dirty_list_.push_back(current_entry);
                // current_entry->put();               
            }
            break;
        }

    }
    
    if (counter != count) {
        return E_INVAL;
    }

    return startblock;

}
