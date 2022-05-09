#include "u-lib.hh"

#define FUTEX_WAIT      101
#define FUTEX_WAKE      102
 
// This test file is going to time two things: First, use futexes for synchronization.
//      Then, use a more inefficient way to achieve basically the same thing.  This test
//      file ensures that my futex implementation is actually fast, as it is supposed to be.

int futex = 5;
int x = 2;
extern uint8_t end[];

int function1(void* placeholder) {
    sys_msleep(100);
 
    // Wake up the sleeping thread
    sys_futex(&futex, 102, 5);
}

int function2(void* placeholder) {
    sys_msleep(100);

    *x = 3;
}
 
int test1() {
    int (*func1)(void*) = function1;
    char* stack1 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 16 * PAGESIZE
    );
    sys_clone(function1, nullptr, stack1);
 
    // block current thread until the second thread wakes it up
    sys_futex(&futex, 101, 5);
    // End timer right here
    sys_exit(0);
}

int test2() {
    int (*func2)(void*) = function2;
    char* stack2 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 16 * PAGESIZE
    );
    sys_clone(function2, nullptr, stack2);
    sys_badfutex(x, FUTEX_WAIT, 3);
}

void process_main() {
    unsigned int time1 = test1();
    unsigned int time2 = test2();
    assert (time1 > time2);
    console_printf("test futex passed!\n");
}
