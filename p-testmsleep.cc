#include "u-lib.hh"

static const int order[] = {
    2, 7, 6, 4, 1, 8, 5, 3
};

void process_main() {
    printf("start of proces_main\n");
    // create 8 processes
    int my_idx = 0;
    for (int i = 0; i < 3; ++i) {
        pid_t f = sys_fork();
        assert_ge(f, 0);
        my_idx = (my_idx * 2) + (f == 0);
    }
    printf("done with creating 8 processes\n");

    // each process sleeps for `100 * order[my_idx]` milliseconds
    int r = sys_msleep(100 * order[my_idx]);
    assert_eq(r, 0);
    printf("done with sys_msleep\n");

    // then prints its position
    printf("%d [pid %d]\n", order[my_idx], sys_getpid());

    if (my_idx == 0) {
        printf("in if statement\n");
        sys_msleep(800);
        console_printf("You should see 8 lines in sequential order.\n");
        console_printf("If you do, then testmsleep succeeded.\n");
    } else {
        printf("in else statement");
        sys_msleep(1000);
    }
    sys_exit(0);
}
