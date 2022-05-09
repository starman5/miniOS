CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------
There are a few examples of shared state that need to be synchronized.  Firstly, the ptable, which stores struct procs (threads), and the real_ptable, which stores real_procs (processes) need to have locks associated with them.  This is because multiple threads might be trying to access these tables at the same time.  Every time we access or change the ptable or real_ptable, either the ptable_lock or the real_ptable_lock need to be locked.

Also, threads share the file descriptor table.  One thread altering the file descriptor table means that other threads in the same process should see that change.  The way I made sure this was the case was I put the vntable in the struct real_proc, rather than the struct proc.  Therefore, if a thread wants to do some VFS operation, it must look for its associated process in the real_ptable, lock the per-process vntable lock, and then enter the per-process vntable.  This lock is necessary because multiple threads in a process might be trying to access the process' vntable at the same time.

Another thing that needs to be synchronized is the pagetable.  Each process is associated with a pagetable, and all threads in a process share that pagetable.  Therefore, multiple threads might be trying to access the process' pagetable, or free the pagetable, or something of the sort.  In order to resolve this, I added a pagetable_lock_ inside real_proc.  Before a thread accesses its pagetable_ field, it must go into its associated real_proc and lock the pagetable_lock_.

Final project - in total, implemented futexes, an inefficient version of "futexes" (for testing purposes), a sys_time() system call (for testing purposes), and a testfile p-testfutex.cc

For the final project, my goal was to implement futexes.  In order to do this, I created a system call, sys_futex(), which takes in 3 arguments: the address of the futex, the futex operation to be performed, and an integer value.  There are two possible operations: FUTEX_WAIT, and FUTEX_WAKE.  In order for the user to make use of a futex, they must first declare a 32 byte integer in memory accessible to all threads that want to make use of the futex.  Then, they can call sys_futex(), passing in the address of the futex integer as well as the operation and the value to check.

I had trouble figuring out how to test this feature.  I decided to test it by comparing the performance of futexes to a polling implementation, to ensure that there is an expected speed boost.  This seemed natural to me because futexes are supposed to be a fast and efficient synchronization mechanism, so this seemed reasonable to test out.  Therefore, I created another system call, sys_inefficient, which has a similar effect to futexes, but which polls instead of blocks.  In p-testfutex.cc, these two methods are used and the performance of a third operation is checked in both cases.  It is expected that when futexes are used, the third operation will happen faster, because less cpu cycles are not wasted due to the spinning of the waiting thread.

This raises another problem - how to measure speed?  I created another system call, sys_time(), which returns the ticks variable at a given point.  Subtracting the time at two points will indicate how much time was spent doing a certain operation.  I recognize this probably does not work for larger time intervals, but as long as the time intervals we are checking are kept small it should be fine.

I also had difficulty implementing futexes until I realized that I needed to compare the value of the futex with the user specified value in an atomic way, using the atomic compare_exchange_strong operation.  This was a source of difficulty which I think I was able to figure out.



Grading notes
-------------