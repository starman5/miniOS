#include "kernel.hh"
#include "k-lock.hh"

#define MIN_ORDER       12
#define MAX_ORDER       21

static spinlock page_lock;
static uintptr_t next_free_pa;

// Block is the basic building block - one block of memory
struct block {
    int order;
    //int state_;
    list_links link_;
   //block(int state_)
   //    : state_(state_) {
    //}
};
// free_blocks is an array of block lists.  Each element is a block list with the same order
list<block, &block::link_> free_blocks[MAX_ORDER - MIN_ORDER + 1];

// page_mega struct contains information about every page
struct page_meta {
    void* addr = nullptr;
    void* root_addr = nullptr;
    int order = 0;
    bool free = true;
};

// all_pages is an array storing information about every page
page_meta all_pages[MEMSIZE_PHYSICAL / PAGESIZE];


// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc() {
    // Fill all_pages and free_blocks
    // ptr = pa2kptr<void*>(next_free_pa);
    // Should I be converting physical memory to virtual memory?
    // I don't think so because we are allocating physical memory and then converting it to virtual memory
    
    auto range = physical_ranges.begin();
    while (range != physical_ranges.end()) {
        if (range->type() == mem_available) {
            // Add it to free_blocks
            // This might pose a problem because I'm rounding order up, which means there could be
            // more memory in free_blocks than in reality
            // Should I be rounding up or rounding down?
            // I don't think this is a problem because we are allocating right amount of memory, just not actually using it all
            int range_order = msb(range->last() - range->first());
            block* new_block;
            new_block->order = range_order;
            free_blocks[range_order - 1].push_back(new_block);
            
            uintptr_t page_addr = range->first();
            assert(page_addr % PAGESIZE == 0);
            int page_index = (page_addr / PAGESIZE) - 1;

            // Initialize all_pages
            // For every range of mem_available memory, we start with one page in all_pages
            // containing meaningful data.  The rest are initialized to nullptr etc
            all_pages[page_index].addr = (void*) page_addr;
            all_pages[page_index].root_addr = (void*) page_addr;
            all_pages[page_index].order = range_order;

        }
        ++range;
    }

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


block* split(int original_order, block* starting_block) {
    if (original_order != starting_block->order) {
        // pop starting_block (the back) from the free_blocks list
        free_blocks[original_order].pop_back();
        block* first_new;
        first_new->order = original_order;
        block* second_new;
        second_new->order = original_order;
        free_blocks[original_order - 1].push_back(first_new);
        free_blocks[original_order - 1].push_back(second_new);
        //return split(original_order, free_blocks[starting_block->order].back());
        return split(original_order, first_new);
    }

    else {
        return free_blocks[original_order].back();
    }

}

void* kalloc(size_t sz) {
    if (sz == 0 || sz > (1 << MAX_ORDER)) {
        return nullptr;
    }

    int order = msb(sz);
    if (order < MIN_ORDER) {
        order = MIN_ORDER;
    }
    
    auto irqs = page_lock.lock();

    // If there are no free blocks with the exact order, find next largest order
    // and split a block of that order into two new blocks with order - 1
    block* return_block;
    if (free_blocks[order - MIN_ORDER].empty()) {
        for (int i = order - MIN_ORDER + 1; i <= MAX_ORDER; i++) {
            if (!free_blocks[i].empty()) {
                //block* newly_freed = free_blocks[i].pop_back();
                block* newly_freed = free_blocks[i].back();
                return_block = split(order, newly_freed);
            }
        }
        // If it gets here, there is no more free memory.  Return nullptr i think
        page_lock.unlock(irqs);
        return nullptr;
    }
    else {
        void* return_block = free_blocks[order - MIN_ORDER].pop_back();
        page_lock.unlock(irqs);
        return return_block;
    }

    page_lock.unlock(irqs);

    if (return_block) {
        // tell sanitizers the allocated page is accessible
        asan_mark_memory(ka2pa((void*) return_block), PAGESIZE, false);
        // initialize to `int3`
        memset((void*) return_block, 0xCC, PAGESIZE);
    }
    //log_printf("Kalloc Address: %p\n", ptr);
    return return_block;
}


uintptr_t find_buddy(void* ptr) {


}

void merge(void* ptr) {
    uintptr_t buddy_addr = find_buddy(ptr);
    int buddy_index = (buddy_addr / PAGESIZE) - 1;
    int page_index = ((uintptr_t) ptr / PAGESIZE) - 1;
    
    // If buddy is free
    if (all_pages[buddy_index].free) {
        // If buddy is to the left, get rid of the current page and merge to the buddy
        if (buddy_addr < (uintptr_t) ptr) {
            free_blocks[all_pages[page_index].order].erase((block*) ptr);

            all_pages[page_index].addr = nullptr;
            all_pages[buddy_index].order += 1;

            merge(all_pages[buddy_index].addr);
        }
        // If buddy is to the right, get rid of the buddy and merge to the current page
        else {
            free_blocks[all_pages[buddy_index].order].erase((block*) buddy_addr);

            all_pages[buddy_index].addr = nullptr;
            all_pages[page_index].order += 1;

            merge(all_pages[page_index].addr);
        }
    }

    // If buddy is not fre
    else {
        // add to free_blocks
        block* new_block;
        int order = all_pages[page_index].order;
        new_block->order = order;
        free_blocks[order].push_back(new_block);
    }
}

// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr) {
    // check to make sure fields are not nullptr
    if (ptr) {
        // tell sanitizers the freed page is inaccessible
        asan_mark_memory(ka2pa(ptr), PAGESIZE, true);
    }

    // uintptr_t root_addr;
    // int root_order;
    // uintptr_t addr;
    // bool free;

    // Can only access page number with ptr information.  Can't access block in free_blocks
   /* assert(ptr % PAGESIZE == 0);
    uintptr_t page_index = ((uintptr_t) ptr / PAGESIZE) - 1;
    
    
    uintptr_t buddy_ptr;
    uintptr_t offset = 2 ** all_pages[page_index].root_order;
    if ()*/
    
    
    
    // should be a question of < or >
    /* ACTUAL COMMENT NO GOOD if (all_pages[page_index].root_addr == all_pages[page_index].addr) {
        buddy_ptr = (uintptr_t) ptr + offset;
        uintptr_t counter_ptr = all_pages[page_index].addr;
        while (counter_ptr != buddy_ptr) {
            uintptr_t local_page_index = ((uintptr_t) counter_ptr / PAGESIZE) - 1;
            if (!all_pages[local_page_index].free) {
                // fail to merge;
            }
            counter_ptr += PAGESIZE;
        }
        // merge
    }

    else {
        buddy_ptr = (uintptr_t) ptr - offset;
    }*/


    log_printf("kfree not implemented yet\n");

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
