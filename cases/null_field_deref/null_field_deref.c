#include <stddef.h>
struct Item { char padding[16]; int value; };
__attribute__((noinline)) int trigger(void) { struct Item *item = NULL; return item->value; }
int main(void) { return trigger(); }
