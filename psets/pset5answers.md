CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------
There are a few examples of shared state that need to be synchronized.  Firstly, the ptable, which stores struct procs (threads), and the real_ptable, which stores real_procs (processes) need to have locks associated with them.  This is because multiple threads might be trying to access these tables at the same time.

Also, threads share the file descriptor table.  One thread altering the file descriptor table means that other threads in the same process should see that change.  The way I made sure this was the case was I put the vntable in the struct real_proc, rather than the struct proc.  Therefore, if a thread wants to do some VFS operation, it must look for its associated process in the real_ptable, lock the per-process vntable lock, and then enter the per-process vntable.  This lock is necessary because multiple threads in a process might be trying to access the process' vntable at the same time.

Another thing that needs to be synchronized is the pagetable.  Each process is associated with a pagetable, and all threads in a process share that pagetable.  Therefore, multiple threads might be trying to access the process' pagetable, or free the pagetable, or something of the sort.  In order to resolve this, I added a pagetable_lock_ inside real_proc.  Before a thread accesses its pagetable_ field, it must go into its associated real_proc and lock the pagetable_lock_.


For the final project, my goal was to implement futexes.  This consists of two main pieces of functionality.  First, there is 



Grading notes
-------------
Really, truly, the threads testfile does work completely sometimes on my local machine.  I have spent hours and hours trying to debug the race conditions that make it fail sometimes, but to no avail.  On the grading server it sometimes works, but it is rare unfortunately.