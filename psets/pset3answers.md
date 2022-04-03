CS 161 Problem Set 3 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset3collab.md`.

Answers to written questions
----------------------------
                                DESIGN DOCUMENT:

INTERFACE:

Each struct proc has an array of vnode* pointers. vnode* vntable_[MAX_FDS];
The index in this array represents the file descriptor.  For example, the vnode*
at the 3rd index represents the vnode* associated with file descriptor 3.

struct vnode {
    int vn_refcount_ = 1;
    int vn_offset_ = 0;
    void* vn_data_ = nullptr;
    vnode_ops* vn_ops_ = nullptr;
    int other_end = -1;
    bool is_pipe = false;
};

struct vnode_ops {
    int (*vop_open)(struct vnode* vn);
    int (*vop_read)(struct vnode* vn, uintptr_t addr, int sz);
    int (*vop_write)(struct vnode* vn, uintptr_t addr, int sz);
};

Each vnode_ops instance is pointed to by one or more vnodes.

Stdin, stdout, and sterr are associated with fd 0, 1, and 2, respectively, for each per process vnode table.  This is enforced because in Chickadee's first process (in kernel start), I set up these file descriptors in the process' vnode table and create the associated vnode and vnode_ops instances.  By the inheritance of file descriptors in fork, all over processes have these file descriptors set up as well.

SYNCHRONIZATION:

All accesses to a struct proc's vntable_ are protected by the struct proc's vntable_lock_.


EVOLUTION:

At first, I had a per process file descriptor array.  If the file descriptor fd was not
open, fdarray[fd] = -1. If the fd was open, fdarray[fd] = fd.  I also had a system wide vnode table, similar to the per process vnode table in my final design, but system wide in nature.  The fdarray was to
be able to in O(1) time determine if a file descriptor was open or not.  However, this added extra
complexity of having to synchronize access to both the fdtable and the vnode table.  It also seemed very
redundant.  So, I removed the fdtable and decided that it would be sufficient to check if
vnodtable[fd] == nullptr in order to see if a file descriptor is open or not.  I also removed the system wide vnode table and instead made a per process vnode table in struct proc.  This made synchronization easier to reason through and to me seemed like a cleaner design, even if it required some extra memory.  I also added other_end to deal with pipes.  This field stores the file descriptor associated with the other end of the pipe.  If the vnode is not associated with a pipe, this field is set to -1.

CONCERNS

I'm not sure if the per process vntable really needs to be locked.  I don't think multiple threads are ever accessing one struct proc's vntable at the same time.  However, we will need this for the future if we implement multiple threads.


Grading notes
-------------
