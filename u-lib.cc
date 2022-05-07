#include "u-lib.hh"

// dprintf
//    Construct a string from `format` and pass it to `sys_write(fd)`.
//    Returns the number of characters printed, or E_2BIG if the string
//    could not be constructed.

int dprintf(int fd, const char* format, ...) {
    char buf[513];
    va_list val;
    va_start(val, format);
    size_t n = vsnprintf(buf, sizeof(buf), format, val);
    if (n < sizeof(buf)) {
        return sys_write(fd, buf, n);
    } else {
        return E_2BIG;
    }
}


// printf
//    Like `printf(1, ...)`.

int printf(const char* format, ...) {
    char buf[513];
    va_list val;
    va_start(val, format);
    size_t n = vsnprintf(buf, sizeof(buf), format, val);
    if (n < sizeof(buf)) {
        return sys_write(1, buf, n);
    } else {
        return E_2BIG;
    }
}


// panic, assert_fail
//     Call the SYSCALL_PANIC system call so the kernel loops until Control-C.

void panic(const char* format, ...) {
    va_list val;
    va_start(val, format);
    char buf[160];
    memcpy(buf, "PANIC: ", 7);
    int len = vsnprintf(&buf[7], sizeof(buf) - 7, format, val) + 7;
    va_end(val);
    if (len > 0 && buf[len - 1] != '\n') {
        strcpy(buf + len - (len == (int) sizeof(buf) - 1), "\n");
    }
    int cpos = consoletype == CONSOLE_NORMAL ? -1 : CPOS(23, 0);
    (void) console_printf(cpos, 0xC000, "%s", buf);
    sys_panic(nullptr);
}

int error_vprintf(int cpos, int color, const char* format, va_list val) {
    return console_vprintf(cpos, color, format, val);
}

void assert_fail(const char* file, int line, const char* msg,
                 const char* description) {
    if (consoletype != CONSOLE_NORMAL) {
        cursorpos = CPOS(23, 0);
    }
    if (description) {
        error_printf("%s:%d: %s\n", file, line, description);
    }
    error_printf("%s:%d: user assertion '%s' failed\n", file, line, msg);
    sys_panic(nullptr);
}


// sys_clone
//    Create a new thread.

pid_t sys_clone(int (*function)(void*), void* arg, char* stack_top) {
    // Save registers in callee saved registers
    register uintptr_t r12 asm("r12") = reinterpret_cast<uintptr_t>(function);
    register int (*fn)(void*) asm("r13") = function;
    //register uintptr_t r14 asm("r14") = reinterpret_cast<uintptr_t>(stack_top);
    
    // Trap into kernel to actually to syscall_clone stuff
    int ret_value = make_syscall(SYSCALL_CLONE, reinterpret_cast<uintptr_t>(stack_top));

    // If in the new thread, run the function
    if (ret_value == 0) {
        //register uintptr_t rsp asm("rsp") = reinterpret_cast<uintptr_t>(stack_top);
        int thing = function(arg);
        make_syscall(SYSCALL_TEXIT, reinterpret_cast<int>(thing));
        // need to take in a status as well.  The function gives a status.  He has a wrapper function
        //sys_texit(function(arg))
    }

    // exit the thread
    //return make_syscall(SYSCALL_TEXIT);
    return ret_value;

    // return value is the only tricky thing here
}
