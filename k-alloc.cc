#include "kernel.hh"
#include "k-lock.hh"
#include "k-vmiter.hh"

// constant parameters
const int MIN_ORDER = 12;
const int MAX_ORDER = 21;
const int NUMBER_OF_FRAMES = MEMSIZE_PHYSICAL / PAGESIZE;

struct memory_block {
    int order;                  // order of the block, between MIN_ORDER and MAX_ORDER
    bool isFree;                // is this block of memory free?
    void* addr;                 // pointer to the high canonical kernel address of this block
    list_links link_;           // used to help link free blocks together
    memory_block* buddy();      // get the buddy of this memory_block
    void coalesce();            // coalesce freed buddies whenever possible

    int getFrameNumber() {      // gets the frame number for this memory_block
        return ka2pa(addr) / PAGESIZE;
    };

};

int calculateMinOrder(size_t sz);        // calculate the smallest order required for an allocation of size sz
memory_block* getBlock(void* addr);      // get the memory_block at addr
void split(int order);                   // split a block of order `order` into two blocks of a smaller order

static spinlock page_lock;

// Helper functions for freeing
void free_process(proc* process);
void free_pagetable(x86_64_pagetable* pt);
void free_user_memory(proc* process);
void free_user_memory(x86_64_pagetable* pt);

// global buddy allocation state
memory_block pages[NUMBER_OF_FRAMES];
list<memory_block, &memory_block::link_> freeMemoryBlocks[MAX_ORDER + 1];

memory_block* memory_block::buddy() {

    void* buddy_ptr = (void*)((uint64_t) addr ^ (1 << order));
    return getBlock(buddy_ptr);
}

int calculateMinOrder(size_t sz) {
    int order = msb(sz - 1);
    if(order < MIN_ORDER) {
        return MIN_ORDER;
    }
    return order;
}

memory_block* getBlock(void* addr) {
    return &pages[ka2pa(addr) / PAGESIZE];
}


void split(int order) {
    // log_printf("split called with order %d\n", order);
    // check to make sure the block is splittable
    assert(order > MIN_ORDER && order <= MAX_ORDER + 1); // its MAX_ORDER + 1 because you could potentially call the split when there are no MAX_ORDER blocks

    if(order > MAX_ORDER) {
        // log_printf("order %d is too big, failing\n", order);
        return;
    }

    // recursively split blocks if there are no blocks of this order
    if(freeMemoryBlocks[order].empty()) {
        split(order + 1);
    }

    memory_block* free_block = freeMemoryBlocks[order].pop_front();
    // log_printf("free block %p\n", free_block);

    if(!free_block) {
        // log_printf("There is no free block\n");
        return;
    }

    // check the free_block to make sure its actually free and of correct order
    assert(free_block->isFree);
    assert(free_block->order == order);

    // find this block's buddy
    free_block->order--;
    memory_block* buddy = free_block->buddy();

    // set up the buddy
    buddy->order = free_block->order;
    // buddy->isFree = true;

    int current_frame = buddy->getFrameNumber();
    for(int frameID = current_frame; frameID < current_frame + MIN_ORDER - order + 1; frameID++) {
        pages[frameID].isFree = true;
        pages[frameID].order = free_block->order;
    }

    // add both blocks to the list
    free_block->link_.reset();
    buddy->link_.reset();
    freeMemoryBlocks[buddy->order].push_front(buddy);
    freeMemoryBlocks[free_block->order].push_front(free_block);
    // log_printf("Pushed two blocks of order %d to linked list\n", buddy->order);
}

void memory_block::coalesce() {
    // log_printf("coalescing\n");
    // already at the biggest block order, nothing to do
    if(order == MAX_ORDER) {
        return;
    }

    // get this block's buddy
    memory_block* buddy = this->buddy();

    // log_printf("this order: %d, buddy order: %d, this ptr: %p, buddy ptr: %p\n", this->order, buddy->order, this->addr, buddy->addr);
    assert(buddy);
    if(!buddy->isFree || buddy->order != order) {
        // log_printf("buddy is not free or order is incorrect: returning\n");
        return;
    }

    // if you reach here, you and buddy are valid and coalescable
    // delete you and buddy from the freeMemoryBlocks list
    // log_printf("Erasing from list\n");
    assert(this->order == buddy->order);
    assert(this->link_.is_linked());
    assert(buddy->link_.is_linked());

    freeMemoryBlocks[this->order].erase(this);
    freeMemoryBlocks[buddy->order].erase(buddy);
    // log_printf("Finished erasing from list\n");

    // increase the order of both blocks
    this->order++;
    buddy->order++;

    // put the combined block back into the freeMemoryBlocks list
    if(addr < buddy->addr) {
        // "this" address represents the start of the new larger block
        int current_frame = this->getFrameNumber();
        // log_printf("Got current frame %d\n", current_frame);
        for(int frameID = current_frame; frameID < current_frame + MIN_ORDER - order + 1; frameID++) {
            // log_printf("In the loop: frameID = %d\n", frameID);
            pages[frameID].isFree = true;
            pages[frameID].order = order;
        }
        this->link_.reset();
        freeMemoryBlocks[this->order].push_back(this);
        this->coalesce();
    }else{
        // the buddy's address represents the start of the new larger block
        int current_frame = buddy->getFrameNumber();
        // log_printf("Got current frame %d\n", current_frame);
        for(int frameID = current_frame; frameID < current_frame + MIN_ORDER - order + 1; frameID++) {
            // log_printf("In the loop: frameID = %d\n", frameID);
            pages[frameID].isFree = true;
            pages[frameID].order = order;
        }
        buddy->link_.reset();
        freeMemoryBlocks[buddy->order].push_back(buddy);
        buddy->coalesce();
    }
}


// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc() {
    auto irqs = page_lock.lock();

    // go through all the physical blocks of the smallest order (individual pages)
    for(int frameID = 0; frameID < NUMBER_OF_FRAMES; frameID++) {
        uintptr_t ptr = (uintptr_t) (frameID * PAGESIZE); // use a void* and cast later instead?
        auto range = physical_ranges.find(ptr);
        bool isAvail = range->type() == mem_available;

        memory_block* current_block = &pages[frameID];
        current_block->order = MIN_ORDER;
        current_block->isFree = isAvail;
        current_block->addr = pa2kptr<void*>(ptr);

        if(isAvail) {
            current_block->link_.reset();
            freeMemoryBlocks[MIN_ORDER].push_back(current_block);
            current_block->coalesce();
        }
    }

    page_lock.unlock(irqs);
    // log_printf("Reaching end of init_kalloc()\n");
}


// kalloc(sz)
//    Allocate and return a pointer to at least `sz` contiguous bytes of
//    memory. Returns `nullptr` if `sz == 0` or on failure.
//
//    The caller should initialize the returned memory before using it.
//    The handout allocator sets returned memory to 0xCC (this corresponds
//    to the x86 `int3` instruction and may help you debug).
//
//    If `sz` is a multiple of `PAGESIZE`, the returned pointer is guaranteed
//    to be page-aligned.
//
//    The handout code does not free memory and allocates memory in units
//    of pages.
void* kalloc(size_t sz) {
    // log_printf("kalloc() is called with size %zu, order %d\n", sz, calculateMinOrder(sz));
    // log_backtrace();

    if(sz == 0){
        return nullptr;
    }

    int order = calculateMinOrder(sz);
    if(order > MAX_ORDER) {
        return nullptr;
    }

    auto irqs = page_lock.lock();
    void* ptr = nullptr;

    // no more blocks of this order are available, so split a bigger block
    if(freeMemoryBlocks[order].empty()) {
        split(order + 1);
    }

    // log_printf("Going to make an allocation of order %d\n", order);
    memory_block* current_block = freeMemoryBlocks[order].pop_front();

    // if current_block is not nullptr (found a free block of this order)
    if(current_block) {
        // check the order, set the pointer to point to this block, mark it as taken
        assert(current_block->order == order);
        ptr = current_block->addr;
        current_block->isFree = false;
    }

    page_lock.unlock(irqs);

    if (ptr) {
        // tell sanitizers the allocated page is accessible
        asan_mark_memory(ka2pa(ptr), (1 << order), false);
        // initialize to `int3`
        memset(ptr, 0xCC, (1 << order));
    }
    // log_printf("kalloc returns %p\n", ptr);
    return ptr;
}


// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr) {
    // log_printf("kfree is called, ptr = %p\n", ptr);
    
    if (!ptr) {
        return;
    }

    // log_printf("kree ptr %p pa ptr %p\n", ptr, kptr2pa(ptr));
    uintptr_t pa_ptr = kptr2pa(ptr);
    // log_printf("kfree is freeing pointer %p\n", pa_ptr);
    auto irqs = page_lock.lock();

    memory_block* current_block = &pages[pa_ptr / PAGESIZE];
    // log_printf("block %p has order %d\n", current_block->addr, current_block->order);
    
    if(current_block->isFree) {
        page_lock.unlock(irqs);
        return;
    }
    assert(current_block->isFree == false);
    current_block->isFree = true;

    current_block->link_.reset();
    freeMemoryBlocks[current_block->order].push_back(current_block);
    current_block->coalesce();

    page_lock.unlock(irqs);

    // tell sanitizers the freed page is inaccessible
    asan_mark_memory(ka2pa(ptr), PAGESIZE, true);
}


void free_process(proc* process) {
    // make sure the ptable is locked and the process is out of the ptable
    assert(ptable_lock.is_locked());
    assert(ptable[process->id_] == nullptr);

    free_user_memory(process);
    // log_printf("finished user memory free for process %d\n", process->id_);
    free_pagetable(process->pagetable_);
    // log_printf("finished pagetable free for process %d\n", process->id_);
    kfree(process);
    // log_printf("finished kfree free for process %d\n", process->id_);
}

void free_pagetable(x86_64_pagetable* pt) {
    // make sure the ptable is locked
    assert(ptable_lock.is_locked());
    
    for(ptiter it(pt); it.low(); it.next()) {
        it.kfree_ptp();
    }

    // free the pointer to the level 4 pagetable, which is not traversed by ptiter
    kfree((void*) pt);
    // log_printf("End freepagetable\n");
}

void free_user_memory(proc* process) {
    free_user_memory(process->pagetable_);
}

void free_user_memory(x86_64_pagetable* pt) {
    // make sure the ptable is locked
    assert(ptable_lock.is_locked());
    for(vmiter it(pt, 0); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        if(it.user() && it.pa() != CONSOLE_ADDR) {
            // log_printf("about to free page at va %p, pa %p, pa2ka %p\n", it.va(), it.pa(), pa2ka(it.pa()));
            it.kfree_page();
        }
    }
    // log_printf("End freeusermem\n");
}


// operator new, operator delete
//    Expressions like `new (std::nothrow) T(...)` and `delete x` work,
//    and call kalloc/kfree.
void* operator new(size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new(size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void operator delete(void* ptr) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}