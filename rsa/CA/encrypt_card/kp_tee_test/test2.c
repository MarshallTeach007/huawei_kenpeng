//
// Created by dongbo on 2023/3/7.
//


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "tee_client_api.h"

static const TEEC_UUID MULTI_CORE_UUID = {
        0xebc87fc2, 0x05dc, 0x41b3,
        {0x85, 0xb9, 0xf9, 0xf0, 0xef, 0x48, 0x1b, 0xad}
};



int testSessions(){

    int ret = 0;
    TEEC_Context context;
    if ((ret = TEEC_InitializeContext(NULL, &context))) {
        printf("teec initial failed\n");
        return ret;
    }

    TEEC_Operation operation = { 0 };
    uint32_t origin = 0;
    operation.started = 1;
    context.ta_path = (uint8_t *)"/home/tee_install/rsa/install/ebc87fc2-05dc-41b3-85b9-f9f0ef481bad.sec";
    TEEC_Session my_session[50];
    for (int i = 0; i < 50; i++) {
        if ((ret = TEEC_OpenSession(&context, &my_session[i], &MULTI_CORE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin))) {
            printf("open session failed: result:%x orgin: %d.\n", ret, origin);
            exit -1;
        } else {
            printf("TEEC_OpenSession \n");
        }
        sleep(5);
    }

    return 0;
}

int main(){
   return testSessions();
}