CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------
There are a few examples of shared state that need to be synchronized.  Firstly, the ptable, which stores struct procs (threads), and the real_ptable, which stores real_procs (processes) need to have locks associated with them.  This is because multiple threads might be trying to access these tables at the same time.  Also, since file descriptors are shared amongst threads, I have made it so that threads must go through their associated processes to complete VFS operations.  Therefore, two threads in the same process might be trying to access the same vntable, which means there must be an associated lock for that vntable to synchronize access to that shared state.


For the final project, my goal was to implement futexes.  This consists of two main pieces of functionality.  First, there is 



Grading notes
-------------
Really, truly, the threads testfile does work completely sometimes on my local machine.  I have spent hours and hours trying to debug the race conditions that make it fail sometimes, but to no avail.  On the grading server it sometimes works, but it is rare unfortunately. Oh well. I tried.