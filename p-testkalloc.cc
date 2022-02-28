#include "u-lib.hh"

extern uint8_t end[];

uint8_t* heap_top;
uint8_t* stack_bottom;

void process_main() {
    // Your code here!
    // Running testkalloc should cause the kernel to run buddy allocator
    // tests. How you make this work is up to you.

    sys_consoletype(CONSOLE_MEMVIEWER);

    //(void) sys_fork();
    //(void) sys_fork();

    heap_top = reinterpret_cast<uint8_t*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE)
    );

    stack_bottom = reinterpret_cast<uint8_t*>(
        round_down(rdrsp() - 1, PAGESIZE)
    );

    //console_printf("heap top: %p\n", heap_top);

    //console_printf("stack bottom %p\n", stack_bottom);

    while(true) {
        for (uint8_t* addr = heap_top ; addr < stack_bottom; addr += PAGESIZE) {
            if (addr != (uint8_t*) 0x200000) {
                //log_printf("addr going into syscall: %p\n", addr);
                if (sys_test_alloc(addr) == -1) {
                    sys_test_free(stack_bottom, heap_top);
                    sys_yield();

                }
            }
        }
        sys_pause();
    }
    //sys_exit(0);
}