#include <stdio.h>
#include <string.h>

static int run_all_tests(void)
{
    printf("[TEST] no tests implemented yet\n");
    return 0;
}

int main(int argc, char** argv)
{
    if (argc > 1 && strcmp(argv[1], "--list") == 0) {
        printf("Available tests:\n");
        printf("  (none - test runner skeleton)\n");
        return 0;
    }
    return run_all_tests();
}
