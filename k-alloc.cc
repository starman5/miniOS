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
    //log_printf("in buddy\n");
    int page_index = p_addr / PAGESIZE;
    int order = all_pages[page_index].order_;  
    if (p_addr % (1 << (order + 1)) == 0) {
        //log_printf("end of buddy\n");
        return p_addr + (1 << order);
    }
    else {
        assert((p_addr - (1 << order)) % (1 << (order + 1)) == 0);
        //log_printf("end of buddy\n");
        return p_addr - (1 << order);
    }
}

    //return (void*)((uintptr_t) (ka2pa(ptr) ^ (1 << all_pages[(uintptr_t)ka2pa(ptr) / PAGESIZE].order_)));


// split
//    Divide blocks until we get one of the proper order

page_meta* split(int original_order, page_meta* starting_block, int count) {
    auto irqs = page_lock.lock();

    //log_printf("In split function\n");

    if (original_order != starting_block->order_) {
        uintptr_t starting_addr = ka2pa(starting_block->addr_);
        uintptr_t starting_index = starting_addr / PAGESIZE;    
        free_blocks[all_pages[starting_index].order_ - MIN_ORDER].erase(&all_pages[starting_index]);

        uintptr_t second_addr = starting_addr + (1 << (all_pages[starting_index].order_ - 1));   
        uintptr_t second_index = second_addr / PAGESIZE;

        uintptr_t third_addr = second_addr + (1 << (all_pages[second_index].order_ - 1));
        uintptr_t third_index = third_addr / PAGESIZE;

        for (int index = starting_index; index < third_index; ++index) {
            all_pages[index].order_ -= 1;
        }
        
        all_pages[starting_index].link_.reset();
        all_pages[second_index].link_.reset();


        //log_printf("starting index order: %i second index order: %i\n", all_pages[starting_index].order_, all_pages[second_index].order_);
        free_blocks[all_pages[starting_index].order_ - MIN_ORDER].push_back(&all_pages[starting_index]);
        free_blocks[all_pages[second_index].order_ - MIN_ORDER].push_back(&all_pages[second_index]);

        page_lock.unlock(irqs);

        return split(original_order, &all_pages[starting_index], count + 1);
    }

    else {
        //assert(free_blocks[original_order - MIN_ORDER].front() != nullptr);
        //log_printf("return value: %p\n", free_blocks[original_order - MIN_ORDER].back());
        page_meta* thing = free_blocks[original_order - MIN_ORDER].pop_back();
        thing->free_ = false;

        page_lock.unlock(irqs);
        return thing;
    }

}



// merge
//      Recursively coalesce free buddies

void merge(uintptr_t p_addr) {
    log_printf("merge pa: %p. va: %p\n", p_addr, pa2kptr<void*>(p_addr));
    //log_printf("In merge\n");
    uintptr_t buddy_phys = find_buddy_pa(p_addr);
    //log_printf("buddy pa: %p, buddy va: %p\n", buddy_phys, pa2kptr<void*>(buddy_phys));
    int buddy_index = (buddy_phys / PAGESIZE);
    uintptr_t page_index = p_addr / PAGESIZE;
    //log_printf("page index in merge: %i\n", page_index);
    //log_printf("before erase\n");
    
    //assert(all_pages[page_index].free_ == true);
    if (all_pages[buddy_index].free_ == true) {
        //log_printf("in if\n");
        //assert(all_pages[page_index].link_.is_linked());
        //log_printf("before erase one\n");
        free_blocks[all_pages[page_index].order_ - MIN_ORDER].erase(&all_pages[page_index]);
        //log_printf("yooo\n");
        //assert(all_pages[buddy_index].link_.is_linked());
        //log_printf("before erase 2\n");
        free_blocks[all_pages[buddy_index].order_ - MIN_ORDER].erase(&all_pages[buddy_index]);
        //log_printf("after erase 2\n");
        //all_pages[buddy_index].link_.reset();
        //log_printf("after erase\n");
        // If buddy is to the left:
        //      Increase the order of the buddy page and add to free_blocks 
        if (buddy_phys < p_addr) {
            int final_index = page_index + (1 << (all_pages[page_index].order_ - MIN_ORDER));
            for (int ind = buddy_index; ind < final_index; ++ind) {
                //log_printf("%i\n", ((1 << (all_pages[page_index].order_ - 1)) / PAGESIZE));
                all_pages[ind].order_ += 1;
                //log_printf("changed order of %p to %i\n", pa2kptr<void*>(ind*PAGESIZE), all_pages[ind].order_);
                //all_pages[ind].free_ = true;
            }

            free_blocks[all_pages[buddy_index].order_ - MIN_ORDER].push_back(&all_pages[buddy_index]);

            merge(buddy_phys);
        }

        // If buddy is to the right:
        //      Increase the order of the current page and add to free_blocks
        else {
            //log_printf("in else\n");
            for (int ind2 = buddy_index; ind2 <= page_index; ++ind2) {
                //log_printf("changing order and free of %p\n", pa2kptr<void*>(ind2*PAGESIZE));
                all_pages[ind2].order_ += 1;
                all_pages[ind2].free_ = true;
            }
            free_blocks[all_pages[page_index].order_ - MIN_ORDER].push_back(&all_pages[page_index]);

            merge(p_addr);
        }
    }
    else {
        //log_printf("in real else\n");
        return;
    }

}



// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.

void init_kalloc() {
    log_printf(" ---- In init_kalloc() ---");
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

    log_printf("End of init kalloc\n");
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
    //log_printf("In kalloc\n");
    //log_printf("size: %i\n", sz);

    if (sz == 0 || sz > (1 << MAX_ORDER)) {
        //log_printf("Not a valid size\n");
        return nullptr;
    }

    int order = msb(sz) - 1;
    if (order < MIN_ORDER) {
        order = MIN_ORDER;
    }

    auto irqs = page_lock.lock();

    // If there are no free blocks with the exact order, find next largest order
    // and split a block of that order into two new blocks with order - 1
    page_meta* return_block = nullptr;
    if (free_blocks[order - MIN_ORDER].front() == nullptr) {
        
        for (int i = order - MIN_ORDER + 1; i <= MAX_ORDER - MIN_ORDER; ++i) {
            //log_printf("in for\n");
            if (free_blocks[i].front() != nullptr) {
                //log_printf("will need to call split\n");
                //log_printf("will get to: %i there is a free block at: %i\n", order, i + MIN_ORDER);
                //log_printf("order of free_blocks[i].back(): %i\n", free_blocks[i].back()->order_);
                //log_printf("order of free_blocks[i+1].back(): %i\n", free_blocks[i+1].back()->order_);
                page_lock.unlock(irqs);
                return_block = split(order, free_blocks[i].back(), 1);
                auto irqs = page_lock.lock();
                if (return_block->addr_) {
                    //log_printf("kernal adress: %p  kernel text: %p  highmem_base: %p\n", return_block->addr_, KTEXT_BASE, HIGHMEM_BASE);
                    asan_mark_memory(ka2pa(return_block->addr_), (1 << return_block->order_), false);
                    memset(return_block->addr_, 0, (1 << return_block->order_));
                }
                page_lock.unlock(irqs);
                return return_block->addr_;
            }
        }

        //log_printf("all lists empty\n");
        page_lock.unlock(irqs);
        return nullptr;
    }
    else {
        //log_printf("there is a free block of this order\n");
        assert(free_blocks[order - MIN_ORDER].front() != nullptr);
        //log_printf("index: %i\n", order - MIN_ORDER);
        return_block = free_blocks[order - MIN_ORDER].pop_back();
        return_block->free_ = false;
        if (return_block->addr_) {
            //log_printf("kernal adress: %p  kernel text: %p  highmem_base: %p\n", return_block->addr_, KTEXT_BASE, HIGHMEM_BASE);
            asan_mark_memory(ka2pa(return_block->addr_), (1 << return_block->order_), false);
            memset(return_block->addr_, 0, (1 << return_block->order_));
        }
        page_lock.unlock(irqs);
        return return_block->addr_;
    }

}



// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr) {
    auto irqs = page_lock.lock();
    log_printf("In kfree.  Freeing virtual address %p associated with physical address %p\n", ptr, ka2pa(ptr));
    // check to make sure fields are not nullptr
    /*if (ptr) {
        // tell sanitizers the freed page is inaccessible
        page_meta* block = (page_meta*) ptr;
        log_printf("block->addr_ is %p\n", block->addr_);
        asan_mark_memory(ka2pa(block->addr_), (1 << block->order_), true);
        memset(block->addr_, 0xCC, (1 << block->order_));
    }*/
    if (ptr) {
        int page_index = (uintptr_t) ka2pa(ptr) / PAGESIZE;
        if (all_pages[page_index].free_ == true) {
            log_printf("the page is already free\n");
            page_lock.unlock(irqs);
            return;
        }
        //log_printf("page index in kfree: %i\n", page_index);
        //log_printf("order of block to be freed: %i\n", all_pages[page_index].order_ - MIN_ORDER);
        int order = all_pages[page_index].order_;
        free_blocks[all_pages[page_index].order_ - MIN_ORDER].push_back(&all_pages[page_index]);
        log_printf("pushed back\n");
        //log_printf("%p %p %p\n", &all_pages[page_index], ka2pa(ptr), ptr);
        //log_printf("read value: %i\n", all_pages[page_index].free_);
        all_pages[page_index].free_ = true;
        //log_printf("after write\n");
        merge(ka2pa(ptr));

        //log_printf("marking memory\n");
        asan_mark_memory(ka2pa(ptr), 1 << order, true);
        //log_printf("after marking memory\n");
        memset(ptr, 0, (1 << order));
        //log_printf("afterm marking memset\n");
    }

    page_lock.unlock(irqs);
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
