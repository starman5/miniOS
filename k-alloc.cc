#include "kernel.hh"
#include "k-lock.hh"

#define MIN_ORDER       12
#define MAX_ORDER       21

static spinlock page_lock;
static uintptr_t next_free_pa;

struct page_meta {
    void* addr_ = nullptr;
    void* root_addr_ = nullptr;
    int order_ = -1;
    bool free_;
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
    auto range = physical_ranges.begin();
    while (range != physical_ranges.end()) {
        if (range->type() == mem_available) {
            int range_order = msb(range->last() - range->first());   
            uintptr_t page_addr = range->first();
            assert(page_addr % PAGESIZE == 0);
            int page_index = (page_addr / PAGESIZE) - 1;
            // Set up the page that is the beginning of the range "block"
            //all_pages[page_index].addr_ = (void*) range->first();
            all_pages[page_index].root_addr_ = (void*) range->first();
            all_pages[page_index].order_ = range_order;
            // Set up all other pages
            for (int local_index = page_index;
                local_index < ((range->last() - 1) / PAGESIZE - 1);
                ++local_index) {

                    all_pages[local_index].link_.reset();
                    all_pages[local_index].free_ = true;
                }
            // Set up lists in free_blocks
            page_meta original_block;
            original_block.addr_ = all_pages[page_index].addr_;
            original_block.root_addr_ =  all_pages[page_index].root_addr_;
            original_block.order_ = all_pages[page_index].order_;
            original_block.free_ =  all_pages[page_index].free_;
            //assert(free_blocks[range_order - 1].front() != nullptr);
            free_blocks[range_order - 1].push_back(&original_block);
        }       
        ++range;
    }
}


page_meta* split(int original_order, page_meta* starting_block) {
    log_printf("In split function\n");
    if (original_order != starting_block->order_) {
        // set address based on starting_block->address
        uintptr_t starting_addr = (uintptr_t) starting_block->addr_;
        uintptr_t starting_index = (uintptr_t) starting_addr / PAGESIZE - 1;
        all_pages[starting_index].order_ -= 1;
        page_meta first_new;
        first_new.addr_ = all_pages[starting_index].addr_;
        first_new.root_addr_ = all_pages[starting_index].root_addr_;
        first_new.order_ = all_pages[starting_index].order_;
        first_new.free_ = all_pages[starting_index].free_;

        uintptr_t second_addr = starting_addr + (1 << all_pages[starting_index].order_);
        uintptr_t second_index = second_addr / PAGESIZE - 1;
        all_pages[second_index].order_ -= 1;
        all_pages[second_index].root_addr_ = (void*) starting_addr;
        page_meta second_new;
        second_new.addr_ = all_pages[second_index].addr_;
        second_new.root_addr_ = all_pages[second_index].root_addr_;
        second_new.order_ = all_pages[second_index].order_;
        second_new.free_ = all_pages[second_index].free_;

        assert(free_blocks[starting_block->order_ - 1].front());
        free_blocks[starting_block->order_ - 1].push_back(&first_new);
        free_blocks[starting_block->order_ - 1].push_back(&second_new);

        return split(original_order, &first_new);
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
        free_blocks[order - MIN_ORDER].reset();
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
    /*uintptr_t buddy_addr = find_buddy(ptr);
    int buddy_index = (buddy_addr / PAGESIZE) - 1;
    int page_index = ((uintptr_t) ptr / PAGESIZE) - 1;
    
    // If buddy is free
    if (all_pages[buddy_index].free) {
        // If buddy is to the left, get rid of the current page and merge to the buddy
        if (buddy_addr < (uintptr_t) ptr) {
            free_blocks[all_pages[page_index].order - 1].erase((block*) ptr);

            all_pages[page_index].addr = nullptr;
            all_pages[buddy_index].order += 1;

            merge(all_pages[buddy_index].addr);
        }
        // If buddy is to the right, get rid of the buddy and merge to the current page
        else {
            free_blocks[all_pages[buddy_index].order - 1].erase((block*) buddy_addr);

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
        free_blocks[order - 1].push_back(new_block);
    }*/
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
