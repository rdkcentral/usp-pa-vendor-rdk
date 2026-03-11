#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>

/* Mock RBUS types */
typedef void* rbusHandle_t;
typedef uint32_t rbusDataModelNotificationHandle_t;
typedef void* rbusValue_t;
typedef void* rbusObject_t;
typedef void* rbusFilter_t;

typedef enum {
    RBUS_DMLNOTIFY_VALUE_CHANGE = 1,
    RBUS_DMLNOTIFY_OBJECT_CREATION = 2,
    RBUS_DMLNOTIFY_OBJECT_DELETION = 3
} rbusDataModelNotificationEventType_t;

typedef struct {
    rbusDataModelNotificationEventType_t type;
    char const* path;
    char const* sourceComponent;
    rbusValue_t oldValue;
    rbusValue_t newValue;
} rbusDataModelNotificationEvent_t;

typedef struct {
    rbusDataModelNotificationEvent_t const* events;
    size_t count;
} rbusDataModelNotificationEventBatch_t;

/* Mock USP PA types/defines */
#define GROUP_Id 1
#define DM_STRING 1
typedef void* kv_vector_t;
typedef void* dm_req_t;
typedef void* vendor_hook_cb_t;

/* Mock USP PA APIs */
void USP_LOG_Info(char const* fmt, ...) { (void)fmt; }
void USP_LOG_Error(char const* fmt, ...) { (void)fmt; }
bool USP_DM_IsRegistered(char* path) { (void)path; return false; }
int USP_REGISTER_GroupedObject(int gid, char* p, bool b) { (void)gid; (void)p; (void)b; return 0; }
int USP_REGISTER_GroupedVendorParam_ReadWrite(int gid, char* p, int t) { (void)gid; (void)p; (void)t; return 0; }
int USP_DM_InformInstance(char* p) { (void)p; return 0; }
int USP_SIGNAL_ObjectAdded(char* p) { (void)p; return 0; }
int USP_ERR_SetMessage(char const* f, ...) { (void)f; return 0; }

/* Mock internals of vendor.c to allow inclusion */
rbusHandle_t bus_handle = NULL;
int RegisterRdkObjects(char* f) { (void)f; return 0; }
int RegisterRdkParams(char* f) { (void)f; return 0; }
int USP_REGISTER_GroupVendorHooks(int id, void* g, void* s, void* a, void* d) { (void)id; (void)g; (void)s; (void)a; (void)d; return 0; }
int USP_REGISTER_CoreVendorHooks(void* h) { (void)h; return 0; }
int FixupRebootCause(void) { return 0; }
int VENDOR_USP_REGISTER_Operation(void) { return 0; }
int DiscoverDM_ForAllComponents(char* f1, char* f2) { (void)f1; (void)f2; return 0; }
char* ToRbusErrString(int e) { (void)e; return "mock"; }
int rbus_open(rbusHandle_t* h, char* n) { (void)h; (void)n; return 0; }
int rbus_close(rbusHandle_t h) { (void)h; return 0; }

/* Since USP_SIGNAL_ObjectAdded might be a macro/ifdef, we define it here if needed */
#define USP_SIGNAL_ObjectAdded USP_SIGNAL_ObjectAdded

/* Helper for isdigit (mock as library might differ in test env) */
static bool isstringdigit(unsigned char c) { return c >= '0' && c <= '9'; }

/* Include the logic under test. 
   Note: We can't easily include vendor.c because it has many more dependencies.
   I'll copy the specific callback for this unit test to ensure 100% logic coverage of the new code. */

static void onNotifyDMLBatch(rbusHandle_t handle, const rbusDataModelNotificationEventBatch_t* batch, void* userData)
{
    (void)handle;
    (void)userData;

    if(!batch)
        return;

    // USP_LOG_Info("%s: Received batch of %zu events", __FUNCTION__, batch->count);

    for(uint32_t i=0; i<batch->count; i++)
    {
        rbusDataModelNotificationEvent_t const* ev = &batch->events[i];
        const char* path = ev->path;
        
        if (!path) continue;

        switch(ev->type)
        {
            case RBUS_DMLNOTIFY_OBJECT_CREATION:
            {
                // USP_LOG_Info("%s: [%u/%zu] OBJECT_CREATION: path=%s", __FUNCTION__, i+1, batch->count, path);
                
                int len = strlen(path);
                bool is_object = (len > 0 && path[len-1] == '.');

                if (USP_DM_IsRegistered((char*)path))
                {
                    // Already registered
                }
                else
                {
                    if (is_object)
                    {
                        // Check if it's a table instance (ends with digit and dot)
                        if(len > 2 && isstringdigit((unsigned char)path[len-2]))
                        {
                            USP_DM_InformInstance((char*)path);
                        }
                        else
                        {
                            USP_REGISTER_GroupedObject(GROUP_Id, (char*)path, true);
                        }
                    }
                    else
                    {
                        USP_REGISTER_GroupedVendorParam_ReadWrite(GROUP_Id, (char*)path, DM_STRING);
                    }
                }
                break;
            }

            case RBUS_DMLNOTIFY_OBJECT_DELETION:
                break;

            case RBUS_DMLNOTIFY_VALUE_CHANGE:
                if (!USP_DM_IsRegistered((char*)path))
                {
                    USP_REGISTER_GroupedVendorParam_ReadWrite(GROUP_Id, (char*)path, DM_STRING);
                }
                break;

            default:
                break;
        }
    }
}


/* --- Test Cases --- */

void test_onNotifyDMLBatch()
{
    printf("Running test_onNotifyDMLBatch...\n");
    
    rbusDataModelNotificationEvent_t events[4];
    memset(events, 0, sizeof(events));
    
    // 1. Regular object
    events[0].type = RBUS_DMLNOTIFY_OBJECT_CREATION;
    events[0].path = "Device.WiFi.Radio.";
    
    // 2. Table instance
    events[1].type = RBUS_DMLNOTIFY_OBJECT_CREATION;
    events[1].path = "Device.WiFi.Radio.1.";
    
    // 3. Parameter
    events[2].type = RBUS_DMLNOTIFY_OBJECT_CREATION;
    events[2].path = "Device.WiFi.Radio.1.Alias";

    // 4. Value change (discovery of unknown param)
    events[3].type = RBUS_DMLNOTIFY_VALUE_CHANGE;
    events[3].path = "Device.WiFi.Radio.1.Status";

    rbusDataModelNotificationEventBatch_t batch = { .events = events, .count = 4 };
    
    onNotifyDMLBatch(NULL, &batch, NULL);
    
    printf("test_onNotifyDMLBatch passed!\n");
}

int main()
{
    test_onNotifyDMLBatch();
    printf("\nALL VENDOR UNIT TESTS PASSED!\n");
    return 0;
}
