#include <stdint.h>
__attribute__((noinline)) int trigger(void) { volatile int *p=(int *)(uintptr_t)0x123456789abcULL; return *p; }
int main(void) { return trigger(); }
