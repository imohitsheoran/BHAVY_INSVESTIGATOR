#include <stdint.h>
__attribute__((noinline)) void recurse(volatile uint64_t n) { volatile char page[4096]; page[0]=(char)n; recurse(n+1); }
int main(void) { recurse(0); }
