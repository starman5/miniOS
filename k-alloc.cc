#include "kernel.hh"
#include "k-lock.hh"

#define MIN_ORDER       12
#define MAX_ORDER       21

static spinlock page_lock;
static uintptr_t next_free_pa;

// Block is the basic building block - one block of memory
struct block {
    int order;
    int state_;
    list_links link_;
    block(int state_)
        : state_(state_) {
    }
};
// free_blocks is an array of block lists.  Each element is a block list with the same order
list<block, &block::link_> free_blocks[MAX_ORDER - MIN_ORDER + 1];

// page_mega struct contains information about every page
struct page_meta {
    uintptr_t root_addr;
    int root_order;
    uintptr_t addr;
    bool free;
};

// all_pages is an array storing information about every page
page_meta all_pages[MEMSIZE_VIRTUAL / PAGESIZE];


// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc() {
    // Fill all_pages and free_blocks

    auto range = physical_ranges.begin();
    while (range != physical_ranges.end()) {
        if (range->type() == mem_available) {
            // Add it to free_blocks
            // This might pose a problem because I'm rounding order up, which means there could be
            // more memory in free_blocks than in reality
            // Should I be rounding up or rounding down?
            int range_order = msb(range->last() - range->first());
            block* new_block;
            new_block->order = range_order;
            free_blocks[range_order].push_back(new_block);
            
            uintptr_t page_addr = range->first();
            int page_number = page_addr / PAGESIZE;

            // Add it to all_pages
            // Is this supposed to be an all_blocks array?
            all_pages[page_number].root_addr = page_addr;
            all_pages[page_number].root_order = range_order;
            all_pages[page_number].addr = page_addr;
            all_pages[page_number].free = true;

            ++range;
        }
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
        return split(original_order, free_blocks[starting_block->order].back());
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

    // If there are no free blocks with the exact order, find next largest order
    // and split a block of that order into two new blocks with order - 1
    if (free_blocks[order - MIN_ORDER].empty()) {
        for (int i = order - MIN_ORDER; i <= MAX_ORDER; i++) {
            if (!free_blocks[i].empty()) {
                block* newly_freed = free_blocks[i].pop_back();
                return split(order, newly_freed);
            }
        }

        // If it gets here, there is no more free memory.  Return nullptr i think
        return nullptr;
    }
    else {
        return free_blocks[order - MIN_ORDER].pop_back();
    }


    if (sz == 0 || sz > PAGESIZE) {
        return nullptr;
    }
    auto irqs = page_lock.lock();
    void* ptr = nullptr;

    // skip over reserved and kernel memory
    auto range = physical_ranges.find(next_free_pa);
    while (range != physical_ranges.end()) {
        if (range->type() == mem_available) {
            // use this page
            ptr = pa2kptr<void*>(next_free_pa);
            //log_printf("Physical address: %p\n", next_free_pa);
            next_free_pa += PAGESIZE;
            break;
        } else {
            // move to next range
            next_free_pa = range->last();
            ++range;
        }
    }

    // range is an iterator because physical_ranges.find() returns an iterator
    // physical_ranges.end() is also an iterator
    // physical_ranges.limit() 
    // Do it without using range line
    


    page_lock.unlock(irqs);

    if (ptr) {
        // tell sanitizers the allocated page is accessible
        asan_mark_memory(ka2pa(ptr), PAGESIZE, false);
        // initialize to `int3`
        memset(ptr, 0xCC, PAGESIZE);
    }
    //log_printf("Kalloc Address: %p\n", ptr);
    return ptr;
}


// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr) {
    if (ptr) {
        // tell sanitizers the freed page is inaccessible
        asan_mark_memory(ka2pa(ptr), PAGESIZE, true);
    }
        
        // Check if buddy is free
        // If buddy is free:
        //      Push one new block to order + 1
        // Otherwise:
        //      Push one new block to order


        // Mark the associated pages as free in all_pages and add to buddy

        // Check if buddy is free
        //    If root_addr is the current page, then the buddy is the left
        //    If root_addr is not the current page, then the buddy is to the right
        // If the buddy is free, then merge 

        // Find buddy helper function

        // Confirm helper function
        

        // Merge helper function:
        // If buddy is free
        //    combine block and buddy
        //    call merge with new combination   



        /*if ((uintptr_t) ptr % PAGESIZE != 0) {
            // Do something
        }

        int page_number = (uintptr_t) ptr / PAGESIZE;
        if (all_pages[page_number + 1].free) {
            block new_block = block(0);
            free_blocks[order].push_back(new_block);
        }


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
