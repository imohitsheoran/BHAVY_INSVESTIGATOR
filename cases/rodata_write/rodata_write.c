__attribute__((noinline)) void trigger(void) { char *p="read only"; p[0]='X'; }
int main(void) { trigger(); }
