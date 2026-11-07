/* Read-only POSIX error convention witness: only own initialized action object. */
#include <spawn.h>
#include <errno.h>
#include <stdio.h>
int main(void) {
  posix_spawn_file_actions_t a;
  int init = posix_spawn_file_actions_init(&a);
  if (init != 0) return 2;
  int invalid = posix_spawn_file_actions_adddup2(&a, -1, 128);
  int destroy = posix_spawn_file_actions_destroy(&a);
  printf("{\"init\":%d,\"invalid_adddup2\":%d,\"EBADF\":%d,\"destroy\":%d}\n", init, invalid, EBADF, destroy);
  return (invalid == EBADF && invalid > 0 && destroy == 0) ? 0 : 3;
}
