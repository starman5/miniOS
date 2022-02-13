CS 161 Problem Set 1 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset1collab.md`.

Answers to written questions
----------------------------
A. Memory Allocator
1. The maximum size supported by kalloc() is 4096 bytes, the size of one page
2. The first address returned by kalloc() is 0xffff800000001000.  This checks out experiementally after utilizing log_printf.  This also makes sense from the code because k-alloc.cc skips over the reserved and kernel memory before identifying the new memory address to use.  It waits for the type of the memory to be mem_available.  Printing out the first physical address returned by kalloc yields 0x2000.  Also, in x86-64.h it defines the minimum high canonial address to be 0xFFFF800000000000UL
3. The largest address returned by kalloc() is 0xffff8000001ff000.
0xffff8000002d3000
4. kalloc() returns high canonical addresses.  This line in k-alloc.cc determines this:
        ptr = pa2kptr<void*>(next_free_pa);
5. In k-init.cc, change this line:
        physical_ranges.set(0, MEMSIZE_PHYSICAL, mem_available);
   to this:
        physical_ranges.set(0, 0x300000, mem_available);
8. If there was no page lock, multiple cpus could mess with the state of memory simultaneously, leading to bad synchronization issues.

B. Memory Viewer
1. The line of code that marks physical page 0x100000 as kernel-restricted:
    mark(pa, f_kernel); -> line 87
2. The line of code that marks struct proc memory as kernel-restricted:
    mark(ka2pa(p), f_kernel | f_process(pid));
3. Ptiter maps the physical addresses of page table pages.  If these addresses were to be marked as user accessible, that would allow unprivileged code to manipulate these page table pages and give itself more privilege or mark as present mappings that don't exist, or do other mischief.  This is not possible in vmiter because vmiter traverses the page table structure using the various indexes to arrive at a particular physical address - not the physical addresses of page table pages.
4. All pages marked by the pid loop should have the same mem_ type constant.  That memory type is mem_available.  They are not mem_kernel because we previously marked kernel memory as kernel-restricted.  They are not mem_nonexistent, because they do exist.  They are not mem_console because they don't belong to the console.  They are not mem_reserved because they are not reserved. They are user-accessible addresses that the user can access.
5. It runs faster because next() skips over holes in processes' virtual adress spaces


C.
Breakpoints:
jmp_Z12kernel_startPKc
call _ZN4proc9exceptionEP8regstate
call _ZN4proc7syscallEP8regstate
call _ZN4proc17panic_nonrunnableEv
call _Z11assert_failPKciS0_S0_
movabsq $_ZN8cpustate7init_apEv, %rbx
movw $boot_start, %sp



Grading notes
-------------
