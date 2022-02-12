#include "kernel.hh"
#include "k-lock.hh"

#define MIN_ORDER       12
#define MAX_ORDER       21

static spinlock page_lock;
static uintptr_t next_free_pa;

struct page_meta {
    void* addr_;
    int order_;
    bool free_;
    list_links link_;
};

list<page_meta, &page_meta::link_> free_blocks[MAX_ORDER - MIN_ORDER + 1];

page_meta all_pages[MEMSIZE_PHYSICAL / PAGESIZE];



// find_buddy
//      Return the buddy associated with the page at ptr

uintptr_t find_buddy_pa(uintptr_t p_addr) {
    int page_index = p_addr / PAGESIZE;
    int order = all_pages[page_index].order_;  
    if (p_addr % (1 << (order + 1)) == 0) {
        return p_addr + (1 << order);
    }
    else {
        assert((p_addr - (1 << order)) % (1 << (order + 1)) == 0);
        return p_addr - (1 << order);
    }
}

    //return (void*)((uintptr_t) (ka2pa(ptr) ^ (1 << all_pages[(uintptr_t)ka2pa(ptr) / PAGESIZE].order_)));


// split
//    Divide blocks until we get one of the proper order

page_meta* split(int original_order, page_meta* starting_block) {
    auto irqs = page_lock.lock();

    log_printf("In split function\n");
    log_printf("original_order: %i starting_order: %i\n", original_order, starting_block->order_);

    if (original_order != starting_block->order_) {

        uintptr_t starting_addr = ka2pa(starting_block->addr_);
        uintptr_t starting_index = starting_addr / PAGESIZE;
        log_printf("original order: %i order: %i\n", original_order, all_pages[starting_index].order_);
        all_pages[starting_index].order_ -= 1;
        all_pages[starting_index].link_.reset();
    
        uintptr_t second_addr = (starting_addr + (1 << all_pages[starting_index].order_));
        uintptr_t second_index = second_addr / PAGESIZE;
        all_pages[second_index].order_ -= 1;
        all_pages[second_index].link_.reset();


        log_printf("starting index order: %i second index order: %i\n", all_pages[starting_index].order_, all_pages[second_index].order_);
        free_blocks[all_pages[starting_index].order_ - MIN_ORDER].push_back(&all_pages[starting_index]);
        free_blocks[all_pages[starting_index].order_ - MIN_ORDER].push_back(&all_pages[second_index]);

        page_lock.unlock(irqs);

        return split(original_order, &all_pages[starting_index]);
    }

    else {
        assert(free_blocks[original_order - MIN_ORDER].front() != nullptr);
        page_lock.unlock(irqs);
        return free_blocks[original_order - MIN_ORDER].pop_back();
    }

}



// merge
//      Recursively coalesce free buddies

void merge(uintptr_t p_addr) {
    log_printf("In merge\n");
    uintptr_t buddy_phys = find_buddy_pa(p_addr);
    int buddy_index = (buddy_phys / PAGESIZE);
    uintptr_t page_index = p_addr / PAGESIZE;
    
    //assert(all_pages[page_index].free_ == true);
    if (all_pages[buddy_index].free_ == true) {
        log_printf("if\n");
        //assert(all_pages[page_index].link_.is_linked());
        free_blocks[all_pages[page_index].order_ - MIN_ORDER].erase(&all_pages[page_index]);

        //assert(all_pages[buddy_index].link_.is_linked());
        free_blocks[all_pages[buddy_index].order_ - MIN_ORDER].erase(&all_pages[buddy_index]);
        //all_pages[buddy_index].link_.reset();
        
        // If buddy is to the left:
        //      Increase the order of the buddy page and add to free_blocks 
        if (buddy_phys < p_addr) {
            log_printf("before addition: %i\n", all_pages[buddy_index].order_);
            all_pages[buddy_index].order_ += 1;
            log_printf("after addition: %i\n", all_pages[buddy_index].order_);
            free_blocks[all_pages[buddy_index].order_ - MIN_ORDER].push_back(&all_pages[buddy_index]);

            merge(buddy_phys);
        }

        // If buddy is to the right:
        //      Increase the order of the current page and add to free_blocks
        else {
            all_pages[page_index].order_ += 1;
            free_blocks[all_pages[page_index].order_ - MIN_ORDER].push_back(&all_pages[page_index]);

            merge(p_addr);
        }
    }

    else {
        log_printf("else\n");
        return;
    }
}



// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.

void init_kalloc() {
    auto irqs = page_lock.lock();

    for (uintptr_t p_addr = 0; p_addr < MEMSIZE_PHYSICAL; p_addr += PAGESIZE) {
        int page_index = p_addr / PAGESIZE;
        all_pages[page_index].addr_ = pa2kptr<void*> (p_addr);
        all_pages[page_index].order_ = MIN_ORDER;
        all_pages[page_index].free_ = false;
    }

    for (int phys_addr = 0; phys_addr < MEMSIZE_PHYSICAL; phys_addr += PAGESIZE) {
        int page_index = phys_addr / PAGESIZE;
        auto range = physical_ranges.find(phys_addr);

        if (range->type() == mem_available) {
            all_pages[page_index].free_ = true;
            all_pages[page_index].link_.reset();
            free_blocks[0].push_back(&all_pages[page_index]);
            merge(phys_addr);
        }
    }

    /*for (int i = 0; i < MEMSIZE_PHYSICAL; i += PAGESIZE) {
        log_printf("Page: order: %i, address: %p\n", all_pages[i / PAGESIZE].order_, all_pages[i / PAGESIZE].addr_);
    }*/
    /*page_meta* pg;
    for (int i = 0; i < MAX_ORDER - MIN_ORDER; i++) {
        while (free_blocks[i].front() != nullptr) {
            pg = free_blocks[i].pop_back();
            log_printf("index order: %i order: %i\n", i + MIN_ORDER, pg->order_);
        }
    }*/
    log_printf("END of init kalloc\n");
    page_lock.unlock(irqs);
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
    log_printf("In kalloc\n");
    log_printf("size: %i\n", sz);

    if (sz == 0 || sz > (1 << MAX_ORDER)) {
        log_printf("Not a valid size\n");
        return nullptr;
    }

    int order = msb(sz);
    if (order < MIN_ORDER) {
        order = MIN_ORDER;
    }

    auto irqs = page_lock.lock();

    // If there are no free blocks with the exact order, find next largest order
    // and split a block of that order into two new blocks with order - 1
    page_meta* return_block;
    if (free_blocks[order - MIN_ORDER].front() == nullptr) {
        log_printf("in the if\n");
        
        for (int i = order - MIN_ORDER + 1; i <= MAX_ORDER - MIN_ORDER; ++i) {
            if (free_blocks[i].front() != nullptr) {
                page_lock.unlock(irqs);
                log_printf("will get to: %i there is a free block at: %i\n", order, i + MIN_ORDER);
                log_printf("order of free_blocks[i].back(): %i\n", free_blocks[i].back()->order_);
                //log_printf("order of free_blocks[i+1].back(): %i\n", free_blocks[i+1].back()->order_);
                return_block = split(order, free_blocks[i].back());
                if (return_block->addr_) {
                    log_printf("kernal adress: %p  kernel text: %p  highmem_base: %p\n", return_block->addr_, KTEXT_BASE, HIGHMEM_BASE);
                    asan_mark_memory(ka2pa(return_block->addr_), PAGESIZE, false);
                    memset(return_block->addr_, 0xCC, PAGESIZE);
                }
                return return_block->addr_;
            }
        }

        page_lock.unlock(irqs);
        return nullptr;
    }
    else {
        log_printf("in the else\n");
        assert(free_blocks[order - MIN_ORDER].front() != nullptr);
        log_printf("addddd: %p\n", free_blocks[order - MIN_ORDER].front()->addr_);
        //log_printf("index: %i\n", order - MIN_ORDER);
        return_block = free_blocks[order - MIN_ORDER].pop_back();
        log_printf("pop back addr: %p\n", return_block);
        log_printf("return block addr: %p\n", return_block->addr_);
        page_lock.unlock(irqs);
        log_printf("got here\n");
        log_printf("return block: %p\n", return_block->addr_);
        if (return_block->addr_) {
            log_printf("kernal adress: %p  kernel text: %p  highmem_base: %p\n", return_block->addr_, KTEXT_BASE, HIGHMEM_BASE);
            asan_mark_memory(ka2pa(return_block->addr_), PAGESIZE, false);
            memset(return_block->addr_, 0xCC, PAGESIZE);
        }
        return return_block->addr_;
    }
    //page_lock.unlock(irqs);

    /*if (return_block) {
        // tell sanitizers the allocated page is accessible
        asan_mark_memory(ka2pa((void*) return_block), PAGESIZE, false);
        // initialize to `int3`
        memset((void*) return_block, 0xCC, PAGESIZE);
    }

    return return_block;*/
    //log_printf("end of kalloc\n");
}



// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr) {
    log_printf("In kfree\n");
    // check to make sure fields are not nullptr
    if (ptr) {
        // tell sanitizers the freed page is inaccessible
        asan_mark_memory(ka2pa(ptr), PAGESIZE, true);
    }
    int page_index = (uintptr_t) ka2pa(ptr) / PAGESIZE;
    log_printf("%i\n", all_pages[page_index].order_ - MIN_ORDER);
    free_blocks[all_pages[page_index].order_ - MIN_ORDER].push_back(&all_pages[page_index]);
    merge(ka2pa(ptr));
    return;
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
