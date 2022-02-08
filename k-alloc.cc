#include "kernel.hh"
#include "k-lock.hh"

#define MIN_ORDER       12
#define MAX_ORDER       21

static spinlock page_lock;
static uintptr_t next_free_pa;

// Block is the basic building block - one block of memory
struct block {
    int state_;
    list_links link_;
    block(int state_)
        : state_(state_) {
    }
};

// An order is a list of blocks with the same order
struct order {
    int order_;
    list<block, &block::link_> block_list_;
    list_links link_;   
};

// free_blocks is a list of orders.  There are MAX_ORDER - MIN_ORDER
// orders in free_blocks
list<order, &order::link_> free_blocks[MAX_ORDER - MIN_ORDER];


struct page {
    uintptr_t addr;
    bool free;
};

// all_pages is an array storing information about every page
//list<page, &page::link_> all_pages[MEMSIZE_VIRTUAL / PAGESIZE];


// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc() {
    // Ensure that kalloc has access to all physical memory with type MEM_AVAILABLE
    // in physical_ranges

    /*auto range = physical_ranges.begin();

    while (range != physical_ranges.end()) {
        if (range->type() == mem_available) {
            int difference;
        }
    }*/

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
    /*if (sz == 0 || sz > (1 << MAX_ORDER)) {
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
                free_blocks[i].erase(free_blocks[i].back());
                
                block first_new(0);
                block second_new(0);
                free_blocks[i-1].push_back(&first_new);
                free_blocks[i-1].push_back(&second_new);
                kalloc(sz);
            }
        }

        // There is no more free memory.  Do bad stuff
    }
    else {
        return free_blocks[order - MIN_ORDER].back();
    }*/

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


        // Check a buddy:
        // Size of block is 2^order
        // So address of buddy is address of current block + 2^order
        // We need a data structure keeping track of this information

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
