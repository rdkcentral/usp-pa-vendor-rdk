#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rbus.h>

#define NUM_PARAMS 5000

static rbusError_t get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle; (void)opts;
    rbusValue_t value;
    rbusValue_Init(&value);
    rbusValue_SetString(value, "StressValue");
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

int main(int argc, char** argv)
{
    rbusHandle_t handle;
    rbusError_t err;
    int num_params = NUM_PARAMS;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if(argc > 1) num_params = atoi(argv[1]);

    fprintf(stderr, "Stress Provider: Initializing %d parameters...\n", num_params);

    err = rbus_open(&handle, "StressProvider");
    if(err != RBUS_ERROR_SUCCESS)
    {
        fprintf(stderr, "rbus_open failed: %d\n", err);
        return -1;
    }

    fprintf(stderr, "Stress Provider: Waiting 120s for discovery to bind...\n");
    sleep(120);

    fprintf(stderr, "Stress Provider: Beginning batch registration of %d parameters...\n", num_params);
    int batch_size = 100;
    for(int b = 0; b < num_params; b += batch_size)
    {
        int current_batch = (b + batch_size > num_params) ? (num_params - b) : batch_size;
        rbusDataElement_t* elements = calloc(current_batch, sizeof(rbusDataElement_t));
        for(int i = 0; i < current_batch; i++)
        {
            char* name = malloc(64);
            sprintf(name, "Device.Stress.Param.%d", b + i + 1);
            elements[i].name = name;
            elements[i].type = RBUS_ELEMENT_TYPE_PROPERTY;
            elements[i].cbTable.getHandler = get_handler;
        }

        err = rbus_regDataElements(handle, current_batch, elements);
        if(err != RBUS_ERROR_SUCCESS)
            fprintf(stderr, "rbus_registerDataElements batch %d failed: %d\n", b/batch_size, err);
        else
            fprintf(stderr, "Stress Provider: Registered batch %d (%d parameters)\n", b/batch_size + 1, current_batch);

        free(elements);
        sleep(5); // Increased delay between batches
    }

    fprintf(stderr, "Stress Provider: All parameters registered. Idling...\n");

    // Keep running
    while(1)
    {
        sleep(10);
    }

    rbus_close(handle);
    return 0;
}
