#ifndef CHICKADEE_K_WAIT_HH
#define CHICKADEE_K_WAIT_HH
#include "kernel.hh"
#include "k-waitstruct.hh"

// k-wait.hh
//    Defines `waiter` and `wait_queue` member functions.
//    `k-waitstruct.hh` defines the `waiter` and `wait_queue` types.
//    (Separating the structures and functions into different header files
//    avoids problems with circular dependencies.)


inline waiter::waiter() {
}

inline waiter::~waiter() {
    // optional error-checking code
}

inline void waiter::prepare(wait_queue& wq) {
    // your code here
    p_ = current();
    //log_printf("p_: %p\n", current());
    //assert(&wq);
    //assert(wq_);
    wq_ = &wq;
    auto irqs = wq.lock_.lock();
    log_printf("in prepare\n");
    //log_printf("wq_: %p\n", wq_);
    //auto irqs = wq.lock_.lock();
    p_->pstate_ = proc::ps_blocked;
    //log_printf("pstate_: %i\n", this->p_->pstate_);
    //assert(wq_);
    wq_->q_.push_back(this);
    //assert(wq.q_.front());
    //assert(wq_ == &wq);
    //log_printf("end prepare\n");
    //log_printf("vnlock: %i, ptlock: %i\n", current()->vntable_lock_.is_locked(), ptable_lock.is_locked());
    wq_->lock_.unlock(irqs);
    //log_printf("after unlocking\n");
}

inline void waiter::block() {
    log_printf("bru\n");
    //assert(p_ == current());
    // your code here
    log_printf("in block\n");
    //log_printf("p: %p\n", p_);
    if (p_->pstate_ == proc::ps_blocked) {
        log_printf("about to yield\n");
        //assert(!p_->fdtable_lock_.is_locked()); 
        //assert(!p_->vntable_lock_.is_locked());
        //assert(!wq_->lock_.is_locked());
        //assert(!ptable_lock.is_locked());
        p_->yield();
    }
    else {
    }
    clear();
}

inline void waiter::clear() {
    // your code here
    //log_printf("in clear\n");
    auto irqs = wq_->lock_.lock();
    //log_printf("will wake in clean\n");
    //log_printf("right here\n");
    if (this->links_.is_linked()) {
        wq_->q_.erase(this);
        wake();
    }
    wq_->lock_.unlock(irqs);
    //wq_ = nullptr;

}

inline void waiter::wake() {
    //log_printf("in wake\n");
    //assert(wq_->lock_.is_locked());
    p_->wake();
}


// waiter::block_until(wq, predicate)
//    Block on `wq` until `predicate()` returns true.
template <typename F>
inline void waiter::block_until(wait_queue& wq, F predicate) {
    while (true) {
        //log_printf("in loop\n");
        prepare(wq);
        //log_printf("after prepare\n");
        if (predicate()) {
            break;
        }
        block();
    }
    clear();
}

// waiter::block_until(wq, predicate, lock, irqs)
//    Block on `wq` until `predicate()` returns true. The `lock`
//    must be locked; it is unlocked before blocking (if blocking
//    is necessary). All calls to `predicate` have `lock` locked,
//    and `lock` is locked on return.
template <typename F>
inline void waiter::block_until(wait_queue& wq, F predicate,
                                spinlock& lock, irqstate& irqs) {
    while (true) {
        //log_printf("in while loop\n");
        prepare(wq);
        //log_printf("after preparee\n");
        if (predicate()) {
            //log_printf("predicate is true\n");
            break;
        }
        //log_printf("here\n");
        //assert(lock.is_locked());
        lock.unlock(irqs);
        //log_printf("before calling block\n");
        block();
        irqs = lock.lock();
    }
    clear();
}

// waiter::block_until(wq, predicate, guard)
//    Block on `wq` until `predicate()` returns true. The `guard`
//    must be locked on entry; it is unlocked before blocking (if
//    blocking is necessary) and locked on return.
template <typename F>
inline void waiter::block_until(wait_queue& wq, F predicate,
                                spinlock_guard& guard) {
    block_until(wq, predicate, guard.lock_, guard.irqs_);
}

// wait_queue::wake_all()
//    Lock the wait queue, then clear it by waking all waiters.
inline void wait_queue::wake_all() {
    spinlock_guard guard(lock_);
    while (auto w = q_.pop_front()) {
        w->wake();
    }
}

#endif
