#include <stdio.h>
#include <stdlib.h>
#include <rbus.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

static char g_val[256] = "TestValue";

static rbusError_t getHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    rbusValue_t v;
    rbusValue_Init(&v);
    rbusValue_SetString(v, g_val);
    rbusProperty_SetValue(property, v);
    rbusValue_Release(v);
    return RBUS_ERROR_SUCCESS;
}

int main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    rbusHandle_t handle;
    rbusError_t err;
    int i, count, batch;
    struct timeval start, end;
    double elapsed;

    if(argc < 2) {
        printf("Usage: %s <count> [batch_size]\n", argv[0]);
        return 1;
    }

    count = atoi(argv[1]);
    batch = (argc > 2) ? atoi(argv[2]) : count;

    char component_name[64];
    sprintf(component_name, "MassProvider_%d", getpid());
    
    int attempts = 0;
    while(attempts < 10) {
        err = rbus_open(&handle, component_name);
        if(err == RBUS_ERROR_SUCCESS) break;
        fprintf(stderr, "rbus_open attempt %d failed: %d. Retrying...\n", attempts+1, err);
        attempts++;
        sleep(1);
    }
    
    if(err != RBUS_ERROR_SUCCESS) {
        fprintf(stderr, "rbus_open failed permanently after %d attempts: %d\n", attempts, err);
        return 1;
    }

    rbusDataElement_t* elements = calloc(batch, sizeof(rbusDataElement_t));
    char** names = calloc(batch, sizeof(char*));

    printf("REGISTER_START,%d\n", count);
    gettimeofday(&start, NULL);

    int remaining = count;
    int base_idx = 0;
    while(remaining > 0) {
        int current_batch = (remaining > batch) ? batch : remaining;
        for(i=0; i<current_batch; i++) {
            names[i] = malloc(128);
            sprintf(names[i], "Device.X_RDK_MassStress.Param_%d", base_idx + i);
            elements[i].name = names[i];
            elements[i].type = RBUS_ELEMENT_TYPE_PROPERTY;
            elements[i].cbTable.getHandler = getHandler;
        }

        err = rbus_regDataElements(handle, current_batch, elements);
        if(err != RBUS_ERROR_SUCCESS) {
            fprintf(stderr, "rbus_regDataElements failed: %d at idx %d\n", err, base_idx);
            break;
        }
        
        remaining -= current_batch;
        base_idx += current_batch;
    }
    
    gettimeofday(&end, NULL);
    elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    printf("REGISTER_END,%.3f\n", elapsed);

    printf("READY_WAITING\n");
    // Keep running until killed
    while(1) sleep(10);

    // Cleanup (though we expect to be killed)
    for(i=0; i<batch; i++) if(names[i]) free(names[i]);
    free(names);
    free(elements);
    rbus_close(handle);
    return 0;
}
