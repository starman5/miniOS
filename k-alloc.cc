#include "kernel.hh"
#include "k-lock.hh"

#define MIN_ORDER       12
#define MAX_ORDER       21

static spinlock page_lock;
static uintptr_t next_free_pa;

struct page_meta {
    void* addr_ = nullptr;
    int order_ = MIN_ORDER;
    bool free_ = false;
    list_links link_;
    
    /*page_meta(void* addr, void* root_addr, int order, bool free)
        : addr_(addr), root_addr_(root_addr), order_(order), free_(free) {
    }*/
    // add methods
};

// Free_blocks is an array of heads to lists.  Can only do specified list operations on it.
// Each list does NOT store a page_meta struct.  It stores a head to a list.  Cannot access fields
list<page_meta, &page_meta::link_> free_blocks[MAX_ORDER - MIN_ORDER + 1];


// all_pages is an array storing information about every page
page_meta all_pages[MEMSIZE_PHYSICAL / PAGESIZE];


// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.

void init_kalloc() {
    log_printf("initializing stuff\n");

    // Set all available_pages to free and add them to free_blocks[0]
    auto range = physical_ranges.begin();
    while (range != physical_ranges.end()) {
        if (range->type() == mem_available) {
            for (int pg_addr = range.first(); pg_addr < range.last(); pg_addr++) {
                all_pages[pg_addr / PAGESIZE].free_ = true;
                free_blocks[0].push_back(&all_pages[pg_addr / PAGESIZE]);
            }
        }
        ++range;
    }

    // Merge all available pages.  This will take care of free_blocks as well
    range = physical_ranges.begin();
    while (range != physical_ranges.end()) {
        if (range->type() == mem_available) {
            merge(range->first());
        }
        ++range;
    }
}


page_meta* split(int original_order, page_meta* starting_block) {
    log_printf("In split function\n");
    if (original_order != starting_block->order_) {
        // set address based on starting_block->address
        uintptr_t starting_addr = (uintptr_t) starting_block->addr_;
        uintptr_t starting_index = (uintptr_t) starting_addr / PAGESIZE;
        all_pages[starting_index].order_ -= 1;
    
        uintptr_t second_addr = starting_addr + (1 << all_pages[starting_index].order_);
        uintptr_t second_index = second_addr / PAGESIZE;
        all_pages[second_index].order_ -= 1;

        //assert(free_blocks[starting_block->order_ - 1].front());
        //all_pages[starting_index].link_.reset();
        //all_pages[second_index].link_.reset();
        free_blocks[starting_block->order_ - MIN_ORDER].push_back(&all_pages[starting_index]);
        free_blocks[starting_block->order_ - MIN_ORDER].push_back(&all_pages[second_index]);

        return split(original_order, &all_pages[starting_index]);
    }

    else {
        return free_blocks[original_order - 1].back();
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
    page_meta* return_block;
    if (!free_blocks[order - MIN_ORDER].front()) {
        log_printf("None of desired order\n");
        for (int i = order - MIN_ORDER + 1; i < MAX_ORDER; ++i) {
            if (!free_blocks[i].front()) {
                page_meta* newly_freed = free_blocks[i].back();
                return_block = split(order, newly_freed);
            }
        }
        // If it gets here, there is no more free memory.  Return nullptr i think
        page_lock.unlock(irqs);
        return nullptr;
    }
    else {
        //free_blocks[order - MIN_ORDER].reset();
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


void* find_buddy(void* ptr) {
    int page_index = (uintptr_t) ptr / PAGESIZE;
    int order = all_pages[page_index].order_;  
    if ((uintptr_t) ptr % (1 << (order + 1)) == 0) {
        return (void*) ((uintptr_t) ptr + (1 << order));
    }
    else {
        assert((uintptr_t) ptr - (1 << order) % (1 << (order + 1)) == 0);
        return (void*) ((uintptr_t) ptr - (1 << order));
    }

}


// there are two options for merge
// option 1: take in a starting point and merge from that point
// option 2: loop through all_pages to see if something can be merged

void merge(void* ptr) {
    void* buddy_addr = find_buddy(ptr);
    int buddy_index = ((uintptr_t) buddy_addr / PAGESIZE);
    int page_index = ((uintptr_t) ptr / PAGESIZE);
    
    assert(all_pages[page_index].free_ == true);
    if (all_pages[buddy_index].free_ == true) {
        all_pages[page_index].link_.erase();
        all_pages[buddy_index].link_.erase();
        
        // If buddy is to the left:
        //      Increase the order of the buddy page and add to free_blocks 
        if ((uintptr_t) buddy_addr < (uintptr_t) ptr) {
            all_pages[buddy_index].order_ += 1;
            free_blocks[all_pages[buddy_index].order_ - MIN_ORDER].push_back(&all_pages[buddy_index]);

            merge(all_pages[buddy_index].addr_);
        }

        // If buddy is to the right:
        //      Increase the order of the current page and add to free_blocks
        else {
            all_pages[page_index].order_ += 1;
            free_blocks[all_pages[page_index].order_ - MIN_ORDER].push_back(&all_pages[page_index]);

            merge(all_pages[page_index].addr_);
        }
    }

    // If buddy is not free
    else {
        // add to free_blocks
        block* new_block;
        int order = all_pages[page_index].order;
        new_block->order = order;
        free_blocks[order - 1].push_back(new_block);
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
