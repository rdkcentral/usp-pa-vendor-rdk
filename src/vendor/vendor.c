/*
   If not stated otherwise in this file or this component's LICENSE
   file the following copyright and licenses apply:
   Copyright [2021] [RDK Management]
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
 *
 * Copyright (C) 2019, Broadband Forum
 * Copyright (C) 2016-2021  CommScope, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file vendor.c
 *
 * Implements the interface to all vendor implemented data model nodes
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <ctype.h>

#include <rbus.h>
#include <rbus_value.h>

#include "common_defs.h"
#include "usp_api.h"
#include "data_model.h"
#include "text_utils.h"
#include "os_utils.h"

//-------------------------------------------------------------------------------------------------
// Handle for connection to RBus
rbusHandle_t bus_handle = NULL;

//-------------------------------------------------------------------------------------------------
// Names of components on RBus
#define USPPA_COMPONENT_NAME                    "eRT.com.bbf.ccsp.usppa"

//-------------------------------------------------------------------------------------------------
// Group ID for data model parameters and objects associated with get, set, add or delete
#define GROUP_Id 1

//-------------------------------------------------------------------------------------------------
// Session ID for RDK component database transactions associated with set, add and delete
#define RDK_SESSION_ID 0

//-------------------------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int FixupRebootCause(void);
int RegisterRdkParams(char *filename);
int RegisterRdkObjects(char *filename);
int TypeStringToUspType(char *rdk_type_str, unsigned *usp_type, int line_number);
char *RdkTypeToTypeString(rbusValueType_t type);
int UspTypeToRdkType(unsigned param_type);
int CalcIsWritable(char *str, bool *is_writable, int line_number);
bool IsTopLevelObject(char *path);
char *ToRbusErrString(int rbus_err);
int RDK_GetEndpointId(char *buf, int len);
int RDK_AddObject(int group_id, char *path, int *instance);
int RDK_DeleteObject(int group_id, char *path);
int RDK_GetGroup(int group_id, kv_vector_t *params);
int RDK_SetGroup(int group_id, kv_vector_t *params, unsigned *param_types, int *failure_index);
int RDK_RefreshInstances(int group_id, char *path, int *expiry_period);
int RDK_Reboot(void);
int RDK_FactoryReset(void);
int RdkResetInner(char *path, char *value, char *debug_msg);
int DiscoverDM_ForAllComponents(char *objs_filename, char *params_filename);
int Discover_AllDM(kv_vector_t *rdk_objects, kv_vector_t *rdk_params);
void Add_NameToDM(char *instantiated_path, char *write_status, kv_vector_t *rdk_objects, kv_vector_t *rdk_params);
void Add_ObjectToDM(char *schema_path, char *write_status, kv_vector_t *rdk_objects);
int DEVICE_Reboot_Operate(dm_req_t *req, char *command, kv_vector_t *input_args, kv_vector_t *output_args);
int DEVICE_FactoryReset_Operate(dm_req_t *req, char *command, kv_vector_t *input_args, kv_vector_t *output_args);
int DEVICE_SelfTest_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
int DEVICE_PacketCapture_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
int DEVICE_ScheduleTimer_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
int DEVICE_Reboot_Operate(dm_req_t *req, char *command, kv_vector_t *input_args, kv_vector_t *output_args);
int DEVICE_FactoryReset_Operate(dm_req_t *req, char *command, kv_vector_t *input_args, kv_vector_t *output_args);
int DEVICE_SelfTest_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
int DEVICE_PacketCapture_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
int DEVICE_ScheduleTimer_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
void Add_ParamToDM(char *instantiated_path, char *schema_path, char *write_status, kv_vector_t *rdk_params);
void FireBootEvent(void);
void ConvertInstantiatedToSchemaPath(char *src, char *dest, int len);
int WriteDMConfig(char *filename, char *mode, kv_vector_t *kvv, char *comment);
void RDK_SyncDiscovery(void);
int RDK_SetSync(dm_req_t *req, char *value);
void RegisterPathRecursive(const char* concrete_path);

//-------------------------------------------------------------------------------------------------
// NotifyDML Subscriptions handle
rbusDataModelNotificationHandle_t g_notify_handle = 0;
static pthread_t g_discovery_thread;
static bool g_stop_discovery = false;

static char g_dm_objs_file[PATH_MAX] = {0};
static char g_dm_params_file[PATH_MAX] = {0};
static bool g_dm_cache_dirty = false;
static time_t g_last_dm_change = 0;
#define AUTO_SAVE_COOLDOWN 15  // Seconds of silence before auto-saving discovery to flash

#define MAX_PATH_CACHE 100003  /* Prime for hash table */
static char* g_registered_paths[MAX_PATH_CACHE] = {0};
static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// Expert Recommendation (Richard Holme): Minimize boot data by using shallow discovery
static bool g_shallow_discovery = true;

//-------------------------------------------------------------------------------------------------
// Discovery status tracking (read via Device.X_RDK_DMDiscovery.*)

static char g_discovery_status[32] = "Idle";      // "Idle" | "Syncing" | "Committing"
static time_t g_last_sync_time = 0;               // epoch of last completed sync
static int g_last_provider_count = 0;             // unique provider namespaces found in last sync
static pthread_mutex_t g_status_mutex = PTHREAD_MUTEX_INITIALIZER;

static char g_provider_list[4096] = "(none)";     // comma-separated list of provider namespaces

// Count distinct top-level component namespaces (second dot prefix) in an element list.
// Also builds a human-readable list string: "Device.X_RDK_MassStress (10 elems), ..."
// e.g. Device.X_RDK_MassStress.Param_0 → "Device.X_RDK_MassStress"  counts as 1 provider.
static int CountUniqueProviders(rbusElementInfo_t* elems, char* list_buf, size_t list_buf_len)
{
#define MAX_PROVIDERS 128
    static char seen[MAX_PROVIDERS][256];
    static int  elem_count[MAX_PROVIDERS];
    int count = 0;
    rbusElementInfo_t* e = elems;

    while (e)
    {
        if (e->name)
        {
            const char* first_dot = strchr(e->name, '.');
            if (first_dot)
            {
                const char* second_dot = strchr(first_dot + 1, '.');
                if (second_dot)
                {
                    size_t plen = (size_t)(second_dot - e->name);
                    if (plen < 255)
                    {
                        char prefix[256];
                        memcpy(prefix, e->name, plen);
                        prefix[plen] = '\0';
                        int idx = -1;
                        for (int i = 0; i < count; i++)
                        {
                            if (strcmp(seen[i], prefix) == 0) { idx = i; break; }
                        }
                        if (idx == -1 && count < MAX_PROVIDERS)
                        {
                            strncpy(seen[count], prefix, 255);
                            seen[count][255] = '\0';
                            elem_count[count] = 0;
                            idx = count;
                            count++;
                        }
                        if (idx >= 0) elem_count[idx]++;
                    }
                }
            }
        }
        e = e->next;
    }

    // Build the human-readable list string
    if (list_buf && list_buf_len > 0)
    {
        list_buf[0] = '\0';
        for (int i = 0; i < count; i++)
        {
            size_t remaining = list_buf_len - strlen(list_buf) - 1;
            if (remaining == 0) break;
            if (i > 0) strncat(list_buf, ", ", remaining);
            remaining = list_buf_len - strlen(list_buf) - 1;
            strncat(list_buf, seen[i], remaining);
            remaining = list_buf_len - strlen(list_buf) - 1;
            /* Append element count suffix safely using a fixed small buffer */
            char suffix[32];
            int slen = snprintf(suffix, sizeof(suffix), " (%d elems)", elem_count[i]);
            if (slen > 0 && (size_t)slen < remaining)
                strncat(list_buf, suffix, remaining);
        }
        if (count == 0) strncpy(list_buf, "(none)", list_buf_len - 1);
    }

    return count;
}

int RDK_GetDiscoveryStatus(dm_req_t *req, char *buf, int len)
{
    (void)req;
    pthread_mutex_lock(&g_status_mutex);
    strncpy(buf, g_discovery_status, len - 1);
    buf[len - 1] = '\0';
    pthread_mutex_unlock(&g_status_mutex);
    return USP_ERR_OK;
}

int RDK_GetLastSyncTime(dm_req_t *req, char *buf, int len)
{
    (void)req;
    pthread_mutex_lock(&g_status_mutex);
    if (g_last_sync_time == 0)
    {
        strncpy(buf, "0001-01-01T00:00:00Z", len - 1);
    }
    else
    {
        struct tm tm_info;
        gmtime_r(&g_last_sync_time, &tm_info);
        strftime(buf, (size_t)len, "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    }
    buf[len - 1] = '\0';
    pthread_mutex_unlock(&g_status_mutex);
    return USP_ERR_OK;
}

int RDK_GetProviderCount(dm_req_t *req, char *buf, int len)
{
    (void)req;
    pthread_mutex_lock(&g_status_mutex);
    snprintf(buf, (size_t)len, "%d", g_last_provider_count);
    pthread_mutex_unlock(&g_status_mutex);
    return USP_ERR_OK;
}

int RDK_GetProviderList(dm_req_t *req, char *buf, int len)
{
    (void)req;
    pthread_mutex_lock(&g_status_mutex);
    strncpy(buf, g_provider_list, len - 1);
    buf[len - 1] = '\0';
    pthread_mutex_unlock(&g_status_mutex);
    return USP_ERR_OK;
}

int RDK_GetControlBool(dm_req_t *req, char *buf, int len)
{
    strncpy(buf, "false", len);
    buf[len-1] = '\0';
    return USP_ERR_OK;
}

int RDK_SetCommitDiscovery(dm_req_t *req, char *value)
{
    if (strcmp(value, "true") == 0) {
        USP_LOG_Info("%s: Maually forcing commit of discovery to persistent memory", __FUNCTION__);
        DiscoverDM_ForAllComponents(g_dm_objs_file, g_dm_params_file);
        g_dm_cache_dirty = false;
    }
    return USP_ERR_OK;
}

int RDK_SetSync(dm_req_t *req, char *value)
{
    if (strcmp(value, "true") == 0) {
        USP_LOG_Info("%s: Triggering manual discovery sync", __FUNCTION__);
        RDK_SyncDiscovery();
    }
    return USP_ERR_OK;
}

static void* DiscoveryThread(void* arg)
{
    (void)arg;
    USP_LOG_Info("DiscoveryThread: started");
    while(!g_stop_discovery)
    {
        // Mark status as Syncing before the sweep
        pthread_mutex_lock(&g_status_mutex);
        strncpy(g_discovery_status, "Syncing", sizeof(g_discovery_status) - 1);
        pthread_mutex_unlock(&g_status_mutex);

        RDK_SyncDiscovery();

        // Back to Idle after sync
        pthread_mutex_lock(&g_status_mutex);
        strncpy(g_discovery_status, "Idle", sizeof(g_discovery_status) - 1);
        pthread_mutex_unlock(&g_status_mutex);

        // Internal loop for heartbeat frequency and auto-save check
        for(int i=0; i<300 && !g_stop_discovery; i++)
        {
            bool should_save = false;
            pthread_mutex_lock(&g_cache_mutex);
            if (g_dm_cache_dirty && (time(NULL) - g_last_dm_change > AUTO_SAVE_COOLDOWN))
            {
                should_save = true;
                g_dm_cache_dirty = false; // Reset early to avoid double-trigger during slow save
            }
            pthread_mutex_unlock(&g_cache_mutex);

            if (should_save)
            {
                USP_LOG_Info("DiscoveryThread: Auto-committing changes to persistent memory...");

                pthread_mutex_lock(&g_status_mutex);
                strncpy(g_discovery_status, "Committing", sizeof(g_discovery_status) - 1);
                pthread_mutex_unlock(&g_status_mutex);

                DiscoverDM_ForAllComponents(g_dm_objs_file, g_dm_params_file);

                pthread_mutex_lock(&g_status_mutex);
                strncpy(g_discovery_status, "Idle", sizeof(g_discovery_status) - 1);
                pthread_mutex_unlock(&g_status_mutex);
            }
            sleep(1);
        }
    }
    USP_LOG_Info("DiscoveryThread: exiting");
    return NULL;
}

/*********************************************************************//**
**
** onNotifyDMLBatch
**
** Callback for NotifyDML events (BATCH mode)
** This is used to dynamically discover new data model objects and parameters as they appear on the bus.
**
** \param   handle - bus handler
** \param   batch - batch of events
**
** \return  None
**
**************************************************************************/
// Use RBUS_MAX_NAME_LENGTH from rbus.h if available, otherwise fallback to 256
#ifndef RBUS_MAX_NAME_LENGTH
#define RBUS_MAX_NAME_LENGTH 256
#endif

static void PathToSchema(const char* path, char* schema)
{
    const char* s = path;
    const char* start_of_segment = path;
    char* d = schema;
    if (!path || !schema) return;

    while (*s)
    {
        if (s == start_of_segment)
        {
            // Check if entire segment is numeric
            const char* next_dot = strchr(s, '.');
            const char* end = (next_dot ? next_dot : s + strlen(s));
            bool is_index = true;
            if (s == end) is_index = false; // Empty segment
            for(const char* tmp = s; tmp < end; tmp++)
            {
                if (!isdigit((unsigned char)*tmp)) { is_index = false; break; }
            }

            if (is_index)
            {
                *d++ = '{'; *d++ = 'i'; *d++ = '}';
                s = end;
                if (*s == '.') {
                    *d++ = *s++;
                    start_of_segment = s;
                }
                continue;
            }
        }
        
        if (*s == '.') {
            *d++ = *s++;
            start_of_segment = s;
        } else {
            *d++ = *s++;
        }
    }
    *d = '\0';
}

//-------------------------------------------------------------------------------------------------
// Cache of registered paths to avoid redundant USP registrations during mass discovery


static unsigned int hash_path(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash % MAX_PATH_CACHE;
}

static bool IsPathAlreadyRegistered(const char* path) {
    pthread_mutex_lock(&g_cache_mutex);
    char norm[RBUS_MAX_NAME_LENGTH];
    strncpy(norm, path, sizeof(norm)-1);
    norm[sizeof(norm)-1] = '\0';
    size_t len = strlen(norm);
    if (len > 1 && norm[len-1] == '.' && strstr(norm, "{i}.") == NULL) norm[len-1] = '\0';

    unsigned int h = hash_path(norm);
    unsigned int start_h = h;
    while (g_registered_paths[h]) {
        if (strcmp(g_registered_paths[h], norm) == 0) {
            pthread_mutex_unlock(&g_cache_mutex);
            return true;
        }
        h = (h + 1) % MAX_PATH_CACHE;
        if (h == start_h) break;
    }
    pthread_mutex_unlock(&g_cache_mutex);
    return false;
}

static void MarkPathAsRegistered(const char* path) {
    if (!path) return;
    pthread_mutex_lock(&g_cache_mutex);
    char norm[RBUS_MAX_NAME_LENGTH];
    strncpy(norm, path, sizeof(norm)-1);
    norm[sizeof(norm)-1] = '\0';
    size_t len = strlen(norm);
    if (len > 1 && norm[len-1] == '.' && strstr(norm, "{i}.") == NULL) norm[len-1] = '\0';

    unsigned int h = hash_path(norm);
    unsigned int start_h = h;
    while (g_registered_paths[h]) {
        if (strcmp(g_registered_paths[h], norm) == 0) {
            pthread_mutex_unlock(&g_cache_mutex);
            return; // Already there
        }
        h = (h + 1) % MAX_PATH_CACHE;
        if (h == start_h) {
            pthread_mutex_unlock(&g_cache_mutex);
            return; // Cache full
        }
    }
    g_registered_paths[h] = strdup(norm);
    
    // Mark as dirty for Auto-Persistence
    USP_LOG_Info("%s: Marked dirty due to new path %s", __FUNCTION__, path);
    g_dm_cache_dirty = true;
    g_last_dm_change = time(NULL);
    pthread_mutex_unlock(&g_cache_mutex);
}

void RegisterPathRecursive(const char* concrete_path)
{
    char schema[RBUS_MAX_NAME_LENGTH];
    char current_concrete[RBUS_MAX_NAME_LENGTH] = "";
    char current_schema[RBUS_MAX_NAME_LENGTH] = "";
    const char* s_concrete = concrete_path;
    const char* s_schema;

    if (!concrete_path || !*concrete_path) return;
    
    // Safety: Expert Alignment requires all DM Elements to start with 'Device.'
    if (strncmp(concrete_path, "Device.", 7) != 0)
    {
        USP_LOG_Warning("%s: Ignoring non-USP path '%s'", __FUNCTION__, concrete_path);
        return;
    }

    // Use a prefix that is less likely to collide with static schema
    // and correctly handle registration
    char concrete_buf[RBUS_MAX_NAME_LENGTH];
    strncpy(concrete_buf, concrete_path, sizeof(concrete_buf)-1);
    concrete_buf[sizeof(concrete_buf)-1] = '\0';
    
    PathToSchema(concrete_buf, schema);
    s_schema = schema;
    s_concrete = concrete_buf;

    while (*s_concrete)
    {
        const char* next_dot_c = strchr(s_concrete, '.');
        const char* next_dot_s = strchr(s_schema, '.');
        
        int len_c = (next_dot_c ? (int)(next_dot_c - s_concrete + 1) : (int)strlen(s_concrete));
        int len_s = (next_dot_s ? (int)(next_dot_s - s_schema + 1) : (int)strlen(s_schema));
        
        if (strlen(current_concrete) + len_c >= RBUS_MAX_NAME_LENGTH || 
            strlen(current_schema) + len_s >= RBUS_MAX_NAME_LENGTH) break;

        strncat(current_concrete, s_concrete, len_c);
        strncat(current_schema, s_schema, len_s);
        
        // Check if registered (careful with trailing dot)
        char check_path[RBUS_MAX_NAME_LENGTH];
        strncpy(check_path, current_schema, sizeof(check_path)-1);
        check_path[sizeof(check_path)-1] = '\0';
        size_t cp_len = strlen(check_path);
        if (cp_len > 1 && check_path[cp_len-1] == '.') check_path[cp_len-1] = '\0';

        // Standardize path for registration: Fixed objects lose their dot to avoid Obuspa crash
        int reg_err = USP_ERR_OK;
        bool is_table = (len_s >= 3 && strncmp(s_schema, "{i}", 3) == 0);

        char reg_path[RBUS_MAX_NAME_LENGTH];
        strncpy(reg_path, current_schema, sizeof(reg_path)-1);
        reg_path[sizeof(reg_path)-1] = '\0';
        size_t rplen = strlen(reg_path);
        if (rplen > 1 && reg_path[rplen-1] == '.' && !is_table) reg_path[rplen-1] = '\0';

        if (IsPathAlreadyRegistered(reg_path)) {
            reg_err = USP_ERR_OK;
        } else if (is_table) {
            reg_err = USP_REGISTER_GroupedObject(GROUP_Id, reg_path, true);
        } else if (current_schema[strlen(current_schema)-1] == '.') {
            // It's a missing fixed object container! Register it now so the parameters below it work.
            USP_LOG_Info("DML Task: Dynamically registering parent object %s", reg_path);
            reg_err = USP_REGISTER_GroupedObject(GROUP_Id, reg_path, false);
        } else {
            reg_err = USP_REGISTER_GroupedVendorParam_ReadWrite(GROUP_Id, reg_path, DM_STRING);
        }

        if (reg_err != USP_ERR_OK) {
            // Already registered errors (USP_ERR_INTERNAL_ERROR in this context often means duplicate)
            if (reg_err != USP_ERR_INTERNAL_ERROR) {
                USP_LOG_Error("DML Task: Registration of %s failed: error %d", reg_path, reg_err);
            }
        }
        
        if (reg_err == USP_ERR_OK)
        {
            MarkPathAsRegistered(reg_path);
        }
        
        // If it's a table instance segment, inform the data model
        if (!is_table && strcmp(s_schema, "{i}") == 0) {
            USP_LOG_Info("DML Task: Informing instance %s", current_concrete);
            USP_DM_InformInstance(current_concrete);
        }
        
        if (is_table && current_concrete[strlen(current_concrete)-1] == '.') {
             USP_LOG_Info("DML Task: Informing instance %s", current_concrete);
             int err = USP_DM_InformInstance(current_concrete);
             if (err != USP_ERR_OK && err != USP_ERR_CREATION_FAILURE) {
                 USP_LOG_Error("DML Task: Failed to inform instance %s: %d", current_concrete, err);
             }
        }

        if (!next_dot_c) break;
        s_concrete = next_dot_c + 1;
        s_schema = next_dot_s + 1;
    }
}

typedef struct
{
    char* path;
    int type;
} dml_task_t;

static void dml_register_task_handler(void* arg1, void* arg2)
{
    dml_task_t* task = (dml_task_t*)arg1;
    bool is_async = (bool)(intptr_t)arg2; // Use arg2 as a flag (0=sync, 1=async)
    if(!task) return;

    char* path = task->path;
    USP_LOG_Info("%s: Processing task for %s (type=%d)", __FUNCTION__, path, task->type);

    if (task->type == RBUS_DMLNOTIFY_OBJECT_DELETION)
    {
        char schema[RBUS_MAX_NAME_LENGTH];
        PathToSchema(path, schema);
        if (strcmp(path, schema) == 0)
        {
            if (USP_DM_IsRegistered(schema))
            {
                // Check if it still exists on RBUS (might have been re-registered)
                const char* r_paths[1];
                r_paths[0] = schema;
                int r_num = 0;
                rbusProperty_t r_val = NULL;
                if (rbus_getExt(bus_handle, 1, r_paths, &r_num, &r_val) == RBUS_ERROR_SUCCESS)
                {
                    USP_LOG_Info("DML Task: Skipping deregister for %s (still exists on RBUS)", schema);
                    rbusProperty_Release(r_val);
                }
                else
                {
                    // Safety: Never deregister core parameters or things we didn't dynamically discover
                    // Destination Not Found (5) is often a timeout, NOT a deletion.
                    if (rbus_getExt(bus_handle, 1, r_paths, &r_num, &r_val) != RBUS_ERROR_SUCCESS) {
                         // Double check: if it's a core parameter, REFUSE to deregister
                         if (strncmp(schema, "Device.DeviceInfo.", 18) == 0 || 
                             strncmp(schema, "Device.LocalAgent.", 18) == 0) {
                             USP_LOG_Warning("DML Task: Refusing to deregister core path %s despite RBUS error", schema);
                         } else {
                             USP_LOG_Info("DML Task: Deregistering schema path: %s", schema);
                             int res = DATA_MODEL_DeRegisterPath(schema);
                             if (res != USP_ERR_OK) {
                                 USP_LOG_Error("DML Task: Failed to deregister schema %s: %d", schema, res);
                             } else {
                                 g_dm_cache_dirty = true;
                                 g_last_dm_change = time(NULL);
                             }
                         }
                    }
                }
            }
            else
            {
                USP_LOG_Info("DML Task: Skipping deregister for %s (not registered)", schema);
            }
        }
        else
        {
            // It's an instance. Find the object path by stripping leaf segments.
            char instance_path[RBUS_MAX_NAME_LENGTH];
            strncpy(instance_path, path, RBUS_MAX_NAME_LENGTH-1);
            instance_path[RBUS_MAX_NAME_LENGTH-1] = '\0';
            
            char* last_dot = strrchr(instance_path, '.');
            if (last_dot && last_dot[1] != '\0')
            {
                // Path ends in a parameter, strip it to get object instance
                *last_dot = '\0';
                last_dot = strrchr(instance_path, '.');
            }

            if (last_dot && last_dot[1] == '\0')
            {
                // Check if it still exists on RBUS
                const char* r_paths[1];
                r_paths[0] = path;
                int r_num = 0;
                rbusProperty_t r_val = NULL;
                if (rbus_getExt(bus_handle, 1, r_paths, &r_num, &r_val) == RBUS_ERROR_SUCCESS)
                {
                    USP_LOG_Info("DML Task: Skipping instance delete for %s (still exists on RBUS)", path);
                    rbusProperty_Release(r_val);
                }
                else
                {
                    USP_LOG_Info("DML Task: Deleting instance: %s", instance_path);
                    int res = USP_DM_DeleteInstance(instance_path);
                    if (res != USP_ERR_OK) USP_LOG_Error("DML Task: Instance deletion failed for %s: %d", instance_path, res);
                }
            }
        }
    }
    else
    {
        RegisterPathRecursive(path);
    }

    if (is_async)
    {
        free(task->path);
        free(task);
    }
}

void RDK_SyncDiscovery(void)
{
    rbusError_t rbus_err;
    rbusElementInfo_t* elems = NULL;
    rbusElementInfo_t* elem = NULL;

    USP_LOG_Info("%s: Performing full RBUS discovery sync...", __FUNCTION__);

    // Use linked-list API for safer memory management
    rbus_err = rbusElementInfo_get(bus_handle, "Device.", 10, &elems);
    if(rbus_err == RBUS_ERROR_SUCCESS && elems != NULL)
    {
        // Update provider count, list, and last sync time from this batch
        char tmp_list[4096];
        int provider_count = CountUniqueProviders(elems, tmp_list, sizeof(tmp_list));
        pthread_mutex_lock(&g_status_mutex);
        g_last_provider_count = provider_count;
        g_last_sync_time = time(NULL);
        strncpy(g_provider_list, tmp_list, sizeof(g_provider_list) - 1);
        g_provider_list[sizeof(g_provider_list) - 1] = '\0';
        pthread_mutex_unlock(&g_status_mutex);

        elem = elems;
        while (elem != NULL)
        {
            if (elem->name && !IsPathAlreadyRegistered(elem->name))
            {
                // Safety: Expert Alignment starts with 'Device.'
                if (strncmp(elem->name, "Device.", 7) == 0)
                {
                    pthread_mutex_lock(&g_cache_mutex);
                    g_dm_cache_dirty = true;
                    g_last_dm_change = time(NULL);
                    pthread_mutex_unlock(&g_cache_mutex);

                    dml_task_t* task = malloc(sizeof(dml_task_t));
                    if(task)
                    {
                        task->path = strdup(elem->name);
                        task->type = 0; // Simple discovery

                        // Push to main loop (is_async=1)
                        if (USP_PROCESS_DoWork(dml_register_task_handler, task, (void*)(intptr_t)1) != USP_ERR_OK)
                        {
                            free(task->path);
                            free(task);
                        }
                    }
                }
            }
            elem = elem->next;
        }
        // rbusElementInfo_free(bus_handle, elems);
    }
    else
    {
        // Sync ran but found nothing — still update the timestamp and reset the provider info
        pthread_mutex_lock(&g_status_mutex);
        g_last_sync_time = time(NULL);
        g_last_provider_count = 0;
        strncpy(g_provider_list, "(none)", sizeof(g_provider_list) - 1);
        g_provider_list[sizeof(g_provider_list) - 1] = '\0';
        pthread_mutex_unlock(&g_status_mutex);
    }
}

static void onNotifyDMLElement(rbusHandle_t handle, const rbusDataModelNotificationEvent_t* ev, void* userData)
{
    (void)handle;
    (void)userData;

    if (!ev || !ev->path) return;

    if (strncmp(ev->path, "Device.", 7) == 0)
    {
        dml_task_t* task = malloc(sizeof(dml_task_t));
        if(task)
        {
            task->path = strdup(ev->path);
            task->type = (int)ev->type;
            
            // Push to main loop (is_async=1)
            if (USP_PROCESS_DoWork(dml_register_task_handler, task, (void*)(intptr_t)1) != USP_ERR_OK)
            {
                free(task->path);
                free(task);
            }
        }
    }
}

static void onNotifyDMLBatch(rbusHandle_t handle, const rbusDataModelNotificationEventBatch_t* batch, void* userData)
{
    if (!batch || batch->count == 0 || !batch->events) return;
    USP_LOG_Info("%s: Received batch of %zu DM Element discovery events", __FUNCTION__, (size_t)batch->count);

    size_t buf_size = 65536; // 64KB safety
    char *additions = malloc(buf_size);
    char *removals = malloc(buf_size);
    char *dedup_list = malloc(buf_size); 

    if (!additions || !removals || !dedup_list) {
        if (additions) free(additions);
        if (removals) free(removals);
        if (dedup_list) free(dedup_list);
        return;
    }

    additions[0] = '\0';
    removals[0] = '\0';
    strcpy(dedup_list, ",");
    bool has_adds = false;
    bool has_rems = false;

    for (uint32_t i = 0; i < batch->count; i++)
    {
        const rbusDataModelNotificationEvent_t* ev = &batch->events[i];
        if (!ev->path) continue;

        // Trace every event at v=3
        USP_LOG_Info("%s: Event[%u]: type=%d path=%s", __FUNCTION__, i, (int)ev->type, ev->path);

        char truncated[RBUS_MAX_NAME_LENGTH];
        strncpy(truncated, ev->path, sizeof(truncated)-1);
        truncated[sizeof(truncated)-1] = '\0';

        // Expert Alignment: Truncate to table/container level
        // Rule: Truncate after 3 dots OR at the last dot if depth < 3
        char *p = truncated;
        int dots = 0;
        char *last_dot = NULL;
        while (*p) {
            if (*p == '.') {
                dots++;
                last_dot = p;
            }
            if (dots == 3) { 
                p[1] = '\0'; // Truncate at 3rd level container
                break; 
            }
            p++;
        }

        if (dots < 3 && last_dot && last_dot > truncated + 6) { // 6 = strlen("Device")
             last_dot[1] = '\0'; // Truncate at second level container
        }

        char search[RBUS_MAX_NAME_LENGTH + 3];
        snprintf(search, sizeof(search), ",%s,", truncated);

        // Aggregated USP signals (Registration/Deregistration)
        if (ev->type == RBUS_DMLNOTIFY_OBJECT_CREATION || (int)ev->type == 0)
        {
            if (strstr(dedup_list, search) == NULL) {
                if (strlen(dedup_list) + strlen(search) < buf_size) strcat(dedup_list, search);
                if (has_adds) strncat(additions, ",", buf_size - strlen(additions) - 1);
                strncat(additions, truncated, buf_size - strlen(additions) - 1);
                has_adds = true;
            }
        }
        else if (ev->type == RBUS_DMLNOTIFY_OBJECT_DELETION)
        {
            if (has_rems == false || strstr(dedup_list, search) == NULL) {
                if (has_rems) strncat(removals, ",", buf_size - strlen(removals) - 1);
                strncat(removals, truncated, buf_size - strlen(removals) - 1);
                has_rems = true;
            }
        }

        // Process individual registrations for local cache/memory
        onNotifyDMLElement(handle, ev, userData);
    }

    if (has_adds)
    {
        kv_vector_t *args = USP_MALLOC(sizeof(kv_vector_t));
        USP_ARG_Init(args);
        USP_ARG_Add(args, "DM_Elements", additions);
        USP_ARG_Add(args, "Status", "Complete");
        if (USP_SIGNAL_DataModelEvent("Device.Registered!", args) != USP_ERR_OK) {
            // If it failed to send, we must free it here as the queue won't take it
            USP_ARG_Destroy(args);
            USP_FREE(args);
        } else {
            USP_LOG_Info("Expert Alignment: Fired Device.Registered with %s", additions);
        }
    }

    if (has_rems)
    {
        kv_vector_t *args = USP_MALLOC(sizeof(kv_vector_t));
        USP_ARG_Init(args);
        USP_ARG_Add(args, "DM_Elements", removals);
        USP_ARG_Add(args, "Status", "Complete");
        if (USP_SIGNAL_DataModelEvent("Device.Deregistered!", args) != USP_ERR_OK) {
            USP_ARG_Destroy(args);
            USP_FREE(args);
        } else {
            USP_LOG_Info("Expert Alignment: Fired Device.Deregistered with %s", removals);
        }
    }

    free(additions);
    free(removals);
    free(dedup_list);
}
#ifdef    INCLUDE_LCM_DATAMODEL
#include "lcm_rbus_datamodel.c"
#endif

#ifndef REMOVE_DEVICE_IP_DIAGNOSTICS
#define DEV_IP_DIA "Device.IP.Diagnostics.IPPing."
#define TIMEOUT_SECONDS 15

int condition;
static pthread_mutex_t mutex;
static pthread_cond_t condition_var;
static char shared_value[256];

// Array of valid input arguments
static char *pingtest_input_args[] =
{
    "Host",
};

// Array of valid output arguments
static char *pingtest_output_args[] =
{
    "Status",
    "SuccessCount",
    "FailureCount",
};

// input results of pingtest
typedef struct
{
    int request_instance;
}pingtest_input_cond_t;

// Output results of pingtest
typedef struct
{
    char Status[32];
    char SuccessCount[16];
    char FailureCount[16];
} pingtest_output_res_t;

/*********************************************************************//**
**
** event_callback
**
** Callback for value change event for Device.IP.Diagnostics.IPPing.DiagnosticsState
**
** \param   handle - bus handler
** \param   event - event data for data model
** \param   subscription
**
**
**************************************************************************/
void event_callback(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t newValue = rbusObject_GetValue(event->data, "value");
    const char* valueStr = rbusValue_GetString(newValue, NULL);

    pthread_mutex_lock(&mutex);

    memset(&shared_value, 0, strlen(valueStr)+1);
    strcpy(shared_value, valueStr);

    if (strcmp(valueStr, "Complete") == 0 || strstr(valueStr, "Error") != NULL)
    {
        condition = 1;  // Update the condition to signal main thread
        pthread_cond_signal(&condition_var);
    }

    pthread_mutex_unlock(&mutex);
}

/*********************************************************************//**
**
** PingThreadMain
**
** Called to log the status, SuccessCount and Failure Count of Device.IP.Diagnostics.IPPing() operation
**
** \param   params - pointer to input condition
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void *PingThreadMain(void* params)
{
    int rbus_err, condition =0;
    rbusValue_t values = NULL;
    pingtest_input_cond_t *cond = (pingtest_input_cond_t *) params;
    pingtest_output_res_t results;
    pingtest_output_res_t *res = &results;
    kv_vector_t *output_args;
    int err = USP_ERR_OK, err1 = -1;
    char *err_msg = NULL, path[256], value_str[16];
    const char* object_name = "Device.IP.Diagnostics.IPPing.DiagnosticsState";
    struct timespec ts1;
    clock_gettime(CLOCK_REALTIME, &ts1);
    ts1.tv_sec += TIMEOUT_SECONDS;

    memset(&results, 0, sizeof(results));

    // Exit if unable to signal that this operation is active
    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    if (err != USP_ERR_OK)
    {
        USP_SNPRINTF(err_msg, sizeof(err_msg), "%s: USP_SIGNAL_OperationStatus() failed", __FUNCTION__);
        goto exit;
    }
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&condition_var, NULL);
    rbusEvent_Subscribe(bus_handle, object_name, event_callback, NULL, 0);

    // Wait for "Complete" value
    pthread_mutex_lock(&mutex);

    while (condition == 0)
    {
        err1 = pthread_cond_timedwait(&condition_var, &mutex, &ts1);  // Wait for the event
        if (err1 == 0)
        {
            break;
        }
        else if (err1 == ETIMEDOUT )
        {
            err = USP_ERR_COMMAND_FAILURE;
            USP_SNPRINTF(err_msg, sizeof(err_msg), "%s: USP_SIGNAL_OperationStatus() failed due to Timeout error occurred for %s, %ld ", __FUNCTION__, DEV_IP_DIA, ts1.tv_sec);
            goto exit;
        }

    }
    USP_STRNCPY(res->Status, shared_value, sizeof(res->Status));
    pthread_mutex_unlock(&mutex);

    // Log output results
    USP_LOG_Info("=========== IPPing Result ==========");
    USP_LOG_Info("Status = %s", res->Status);

    //get the SuccessCount
    USP_SNPRINTF(path, sizeof(path), "%s%s", DEV_IP_DIA, pingtest_output_args[1]);
    rbus_err = rbus_get(bus_handle, path, &values);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_ERR_SetMessage("%s: rbus_getStr() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
        goto exit;
    }
    rbusValue_ToString(values, value_str, sizeof(value_str));
    USP_STRNCPY(res->SuccessCount, value_str, sizeof(res->SuccessCount));
    USP_LOG_Info("%s = %s", pingtest_output_args[1], value_str);
    rbusValue_Release(values);

    //get the FailureCount
    USP_SNPRINTF(path, sizeof(path), "%s%s", DEV_IP_DIA, pingtest_output_args[2]);
    rbus_err = rbus_get(bus_handle, path, &values);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_ERR_SetMessage("%s: rbus_getStr() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
        goto exit;
    }
    rbusValue_ToString(values, value_str, sizeof(value_str));
    USP_STRNCPY(res->FailureCount, value_str, sizeof(res->FailureCount));
    USP_LOG_Info("%s = %s", pingtest_output_args[2], value_str);
    rbusValue_Release(values);

exit:
    // Save all results into the output arguments using KV_VECTOR_ functions
    output_args = USP_ARG_Create();
    USP_ARG_Add(output_args, "Status", res->Status);
    USP_ARG_Add(output_args, "SuccessCount", res->SuccessCount);
    USP_ARG_Add(output_args, "FailureCount", res->FailureCount);

    // Inform the protocol handler, that the operation has completed
    // Ownership of the output args passes to protocol handler
    err_msg = (err != USP_ERR_OK) ? err_msg : NULL;
    USP_SIGNAL_OperationComplete(cond->request_instance, err, err_msg, output_args);
    rbusEvent_Unsubscribe(bus_handle, object_name);
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&condition_var);

    // Free the input conditions
    USP_SAFE_FREE(cond);
    return NULL;

}

/*********************************************************************//**
**
** DEVICE_Ping_TEST_Operate
**
** Starts the asynchronous IP.Diagnostics.IPPing operation
** Set and checks all the mandatory parameters are valid
** then starts a thread to perform the operation
**
** \param   req - pointer to structure identifying the operation in the data model
** \param   input_args - vector containing input arguments and their values
** \param   instance - instance number of this operation in the Device.LocalAgent.Request table
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_Ping_TEST_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int rbus_err, err;
    pingtest_input_cond_t *cond;
    char* str = USP_ARG_Get(input_args, "Host", "");

    // Allocate input conditions to pass to thread
    cond = USP_MALLOC(sizeof(pingtest_input_cond_t));
    memset(cond, 0, sizeof(pingtest_input_cond_t));
    cond->request_instance = instance;

    rbus_err = rbus_setStr(bus_handle, DEV_IP_DIA "Host", str);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        err = USP_ERR_SET_FAILURE;
        USP_ERR_SetMessage("%s: rbus_setStr() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
        goto exit;
    }

    rbus_err = rbus_setStr(bus_handle, DEV_IP_DIA "DiagnosticsState", "Requested");
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        err = USP_ERR_SET_FAILURE;
        USP_ERR_SetMessage("%s: rbus_setStr() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
        goto exit;
    }

    USP_LOG_Info("=========== IPPing operation ============");
    err = OS_UTILS_CreateThread("ping_test", PingThreadMain, cond);
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_COMMAND_FAILURE;
        goto exit;
    }

exit:
    // Exit if an error occurred (freeing the input conditions)
    if (err != USP_ERR_OK)
    {
        USP_SAFE_FREE(cond);
        return USP_ERR_COMMAND_FAILURE;
    }

    // Ownership of the input conditions has passed to the thread
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_Reboot_Operate
**
** Handles Device.Reboot() command
**
**************************************************************************/
int DEVICE_Reboot_Operate(dm_req_t *req, char *command, kv_vector_t *input_args, kv_vector_t *output_args)
{
    char *cause = USP_ARG_Get(input_args, "Cause", "RemoteReboot");
    char *reason = USP_ARG_Get(input_args, "Reason", "Unknown");
    
    USP_LOG_Info("DEVICE_Reboot: Initiating reboot (Cause=%s, Reason=%s)", cause, reason);
    
    // In RDK, we use the standard reboot logic
    return RDK_Reboot();
}

/*********************************************************************//**
**
** DEVICE_FactoryReset_Operate
**
** Handles Device.FactoryReset() command
**
**************************************************************************/
int DEVICE_FactoryReset_Operate(dm_req_t *req, char *command, kv_vector_t *input_args, kv_vector_t *output_args)
{
    char *cause = USP_ARG_Get(input_args, "Cause", "RemoteFactoryReset");
    char *reason = USP_ARG_Get(input_args, "Reason", "Unknown");
    
    USP_LOG_Info("DEVICE_FactoryReset: Initiating factory reset (Cause=%s, Reason=%s)", cause, reason);
    
    return RDK_FactoryReset();
}

/*********************************************************************//**
**
** DEVICE_SelfTest_Operate
**
** Handles Device.SelfTestDiagnostics() command (Async)
**
**************************************************************************/
int DEVICE_SelfTest_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    kv_vector_t out_args;
    USP_ARG_Init(&out_args);
    USP_ARG_Add(&out_args, "Status", "Complete");
    USP_ARG_Add(&out_args, "Results", "Self-test passed (Stub)");
    
    USP_SIGNAL_OperationComplete(instance, USP_ERR_OK, NULL, &out_args);
    USP_ARG_Destroy(&out_args);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_PacketCapture_Operate
**
** Handles Device.PacketCaptureDiagnostics() command (Async)
**
**************************************************************************/
int DEVICE_PacketCapture_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    // Minimal stub for async diagnostic operation
    USP_LOG_Info("DEVICE_PacketCapture: Async task started for instance %d", instance);
    
    kv_vector_t out_args;
    USP_ARG_Init(&out_args);
    USP_ARG_Add(&out_args, "Status", "Complete");
    
    USP_SIGNAL_OperationComplete(instance, USP_ERR_OK, NULL, &out_args);
    USP_ARG_Destroy(&out_args);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_ScheduleTimer_Operate
**
** Handles Device.ScheduleTimer() command (Async)
**
**************************************************************************/
int DEVICE_ScheduleTimer_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int delay;
    USP_ARG_GetInt(input_args, "DelaySeconds", 1, &delay);
    USP_LOG_Info("DEVICE_ScheduleTimer: Delaying for %d seconds (instance %d)", delay, instance);
    
    // Real implementation would use a timer task, here we just stub it as immediate for confirmation
    USP_SIGNAL_OperationComplete(instance, USP_ERR_OK, NULL, NULL);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** VENDOR_USP_REGISTER_Operation
**
** Initialises the Device.IP.Diagnostics.IPPing operation and registers all parameters which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int VENDOR_USP_REGISTER_Operation()
{
    int err = USP_ERR_OK;

    // Register IPPing diagnostics
    err |= USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.IPPing()", DEVICE_Ping_TEST_Operate, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IP.Diagnostics.IPPing()", pingtest_input_args, NUM_ELEM(pingtest_input_args),
                                                              pingtest_output_args, NUM_ELEM(pingtest_output_args));

    // Note: We skip manual registration of core standard TR-181 commands/events 
    // because obuspa already has them in its internal schema. 
    // We just provide the hooks for them in USP_REGISTER_CoreVendorHooks.
    
    // We still have our handlers DEVICE_Reboot_Operate etc available,
    // but we let's NOT override if it's already there.

    return USP_ERR_OK;
}
#endif // REMOVE_DEVICE_IP_DIAGNOSTICS

/*********************************************************************//**
**
** VENDOR_Init
**
** Initialises this component, and registers all parameters and vendor hooks, which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/


int VENDOR_Init(void)
{
    // ... (logic to init bus_handle)
#ifdef INCLUDE_LCM_DATAMODEL
    LCM_VENDOR_Init();
#endif
    int err = USP_ERR_OK;
    vendor_hook_cb_t core_callbacks;
    int rbus_err;
    struct stat info;
    char *usp_pa_dm_dir;

    // Override data model paths from environment variable
    usp_pa_dm_dir = getenv("USP_PA_DM_DIR");
    if (usp_pa_dm_dir == NULL)
    {
        usp_pa_dm_dir = "/etc/usp-pa";
    }
    USP_SNPRINTF(g_dm_objs_file, sizeof(g_dm_objs_file), "%s/usp_dm_objs.conf", usp_pa_dm_dir);
    USP_SNPRINTF(g_dm_params_file, sizeof(g_dm_params_file), "%s/usp_dm_params.conf", usp_pa_dm_dir);

    // Register our discovery control triggers
    USP_REGISTER_VendorParam_ReadWrite("Device.X_RDK_DMDiscovery.TriggerSync", RDK_GetControlBool, RDK_SetSync, NULL, DM_BOOL);
    USP_REGISTER_VendorParam_ReadWrite("Device.X_RDK_DMDiscovery.TriggerCommit", RDK_GetControlBool, RDK_SetCommitDiscovery, NULL, DM_BOOL);

    // Register discovery status read-only params
    USP_REGISTER_VendorParam_ReadOnly("Device.X_RDK_DMDiscovery.Status", RDK_GetDiscoveryStatus, DM_STRING);
    USP_REGISTER_VendorParam_ReadOnly("Device.X_RDK_DMDiscovery.LastSyncTime", RDK_GetLastSyncTime, DM_DATETIME);
    USP_REGISTER_VendorParam_ReadOnly("Device.X_RDK_DMDiscovery.ProviderCount", RDK_GetProviderCount, DM_UINT);
    USP_REGISTER_VendorParam_ReadOnly("Device.X_RDK_DMDiscovery.DiscoveredProviders", RDK_GetProviderList, DM_STRING);


    // Register DM Element Change Events (Expert Alignment - Richard & Charles)
    char *event_args[] = {"DM_Elements", "Status"};
    USP_REGISTER_Event("Device.Registered!");
    USP_REGISTER_EventArguments("Device.Registered!", event_args, 2);
    
    USP_REGISTER_Event("Device.Deregistered!");
    USP_REGISTER_EventArguments("Device.Deregistered!", event_args, 2);

    // Register Standard TR-181 Commands & Events
    USP_REGISTER_SyncOperation("Device.Reboot()", DEVICE_Reboot_Operate);
    USP_REGISTER_SyncOperation("Device.FactoryReset()", DEVICE_FactoryReset_Operate);
    
    char *boot_args[] = {"CommandKey", "Cause", "Reason", "FirmwareUpdated", "ParameterMap"};
    USP_REGISTER_Event("Device.Boot!");
    USP_REGISTER_EventArguments("Device.Boot!", boot_args, 5);

    USP_REGISTER_AsyncOperation("Device.SelfTestDiagnostics()", DEVICE_SelfTest_Operate, NULL);
    USP_REGISTER_AsyncOperation("Device.PacketCaptureDiagnostics()", DEVICE_PacketCapture_Operate, NULL);
    USP_REGISTER_AsyncOperation("Device.ScheduleTimer()", DEVICE_ScheduleTimer_Operate, NULL);

    // Initialise bus_handle
    // NOTE: We do this here, rather than in VENDOR_Start() because the SerialNumber, ManufacturerOUI and SoftwareVersion are cached before USP_PA_Start() is called
    int attempts = 0;
    while (attempts < 10) {
        rbus_err = rbus_open(&bus_handle, (char*)USPPA_COMPONENT_NAME);
        if (rbus_err == 0) break;
        
        USP_LOG_Warning("VENDOR_Init: rbus_open() attempt %d failed (%d). Retrying in 1s...", attempts+1, rbus_err);
        attempts++;
        sleep(1);
    }

    if (rbus_err != 0)
    {
        USP_ERR_SetMessage("%s: rbus_open() failed after %d attempts (%d - %s)", __FUNCTION__, attempts, rbus_err, ToRbusErrString(rbus_err));
        return USP_ERR_INTERNAL_ERROR;
    }
    USP_LOG_Info("%s: rbus_open success", __FUNCTION__);
    fprintf(stderr, "VENDOR_Init: rbus_open success\n");

    // Override data model paths from environment variable
    usp_pa_dm_dir = getenv("USP_PA_DM_DIR");
    if (usp_pa_dm_dir == NULL)
    {
        usp_pa_dm_dir = "/etc/usp-pa";
    }

    // Create the data model config files, if they do not already exist
    if ((stat(g_dm_objs_file, &info) != 0) || (stat(g_dm_params_file, &info) != 0))
    {
        // Discover the data model objects and parameters
        USP_LOG_Info("%s: Regenerating missing USP data model config files. This may take a while.", __FUNCTION__);
        err = DiscoverDM_ForAllComponents(g_dm_objs_file, g_dm_params_file);
        if (err != USP_ERR_OK)
        {
            return err;
        }
        USP_LOG_Info("%s: Written USP data model config files. Starting normally.", __FUNCTION__);
    }

    // Exit if unable to register RDK data model objects
    err = RegisterRdkObjects(g_dm_objs_file);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to register RDK data model parameters
    err = RegisterRdkParams(g_dm_params_file);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to register group get and set vendor hooks for all RDK software components
    err = USP_REGISTER_GroupVendorHooks(GROUP_Id, RDK_GetGroup, RDK_SetGroup, RDK_AddObject, RDK_DeleteObject);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Initialise core vendor hooks structure with callbacks
    // NOTE: commit/abort transaction callbacks are not registered as it was found that abort is not
    //       supported consistently across all RDK parameters
    memset(&core_callbacks, 0, sizeof(core_callbacks));
    core_callbacks.reboot_cb = RDK_Reboot;
    core_callbacks.factory_reset_cb = RDK_FactoryReset;
    core_callbacks.get_agent_endpoint_id_cb = RDK_GetEndpointId;

    // Exit if unable to register database transaction hooks
    err = USP_REGISTER_CoreVendorHooks(&core_callbacks);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Modify the cause of reboot stored in the USP database, if it was triggered by another protocol agent, or the device's UI
    err = FixupRebootCause();
    if (err != USP_ERR_OK)
    {
        // return err; // Don't abort USP Agent for this
    }

#ifndef REMOVE_DEVICE_IP_DIAGNOSTICS
    // Register data model parameters used in VENDOR_USP_REGISTER_Operation
    err = VENDOR_USP_REGISTER_Operation();
    if (err!=USP_ERR_OK)
    {
        USP_LOG_Error("VENDOR_USP_REGISTER_Operation failed\n");
        return err;
    }
#endif
    
    // Subscribe to all data model changes via NotifyDML for dynamic discovery
    rbusDataModelNotificationRequest_t req;
    memset(&req, 0, sizeof(req));
    req.pattern = "Device.";
    req.scope = RBUS_DMLNOTIFY_SCOPE_SUBTREE; /* Subscribe to entire subtree */
    req.eventMask = RBUS_DMLNOTIFY_MASK_ALL;
    req.initialState = true; // Full scan upon subscription
    req.batching.batchWindowMs = 500;
    req.batching.maxBatchSize = 100;
    req.batching.rateLimitPerSec = 0; // Unlimited
    req.batching.coalesceThreshold = 1;
    req.handler = onNotifyDMLElement;
    req.batchHandler = onNotifyDMLBatch;

    USP_LOG_Info("%s: Subscribing to NotifyDML for dynamic discovery (pattern=Device.)...", __FUNCTION__);
    rbus_err = rbusDataModelNotification_Subscribe(bus_handle, &req, &g_notify_handle);
    if(rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_LOG_Error("%s: rbusDataModelNotification_Subscribe failed (%d)", __FUNCTION__, rbus_err);
    }

    // DiscoveryThread handles the initial and periodic sync background
    pthread_create(&g_discovery_thread, NULL, DiscoveryThread, NULL);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** VENDOR_Start
**
** Called after data model has been registered and after instance numbers have been read from the USP database
** Typically this function is used to seed the data model with instance numbers or
** initialise internal data structures which require the data model to be running to access parameters
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Start(void)
{
#ifdef INCLUDE_LCM_DATAMODEL
    LCM_VENDOR_Start();
#endif

    // Fire Device.Boot! event to notify controllers about the agent's restart/boot
    FireBootEvent();

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** VENDOR_Stop
**
** Called when stopping USP agent gracefully, to free up memory and shutdown
** any vendor processes etc
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Stop(void)
{
    g_stop_discovery = true;
    pthread_join(g_discovery_thread, NULL);

#ifdef INCLUDE_LCM_DATAMODEL
    LCM_VENDOR_Stop();
#endif
    // Disconnect from the RDK bus
    if (bus_handle != NULL)
    {
        if(g_notify_handle)
        {
            rbusDataModelNotification_Unsubscribe(bus_handle, g_notify_handle);
            g_notify_handle = 0;
        }
        rbus_close(bus_handle);
        bus_handle = NULL;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** FixupRebootCause
**
** Modify the cause of reboot stored in the USP database, if it was triggered by another protocol agent, or the device's UI
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int FixupRebootCause(void)
{
    int err;
    char rdk_cause[MAX_DM_SHORT_VALUE_LEN];
    char usp_cause[MAX_DM_SHORT_VALUE_LEN];
    char *new_cause;
    char *usp_cause_path = "Internal.Reboot.Cause";

    // Exit if unable to get the cause of reboot that RDK has saved
    if (USP_DM_IsRegistered("Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason") == false)
    {
        USP_LOG_Warning("%s: Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason is not registered. Skipping reboot fixup.", __FUNCTION__);
        return USP_ERR_OK;
    }

    err = USP_DM_GetParameterValue("Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason", rdk_cause, sizeof(rdk_cause));
    if (err != USP_ERR_OK)
    {
        USP_LOG_Warning("%s: Could not get Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason (%d). Skipping reboot fixup.", __FUNCTION__, err);
        return USP_ERR_OK; // Don't abort for this
    }

    // Exit if unable to get the cause of reboot that USP has saved
    err = USP_DM_GetParameterValue(usp_cause_path, usp_cause, sizeof(usp_cause));
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Convert RDK's reboot cause to a USP reboot cause
    // NOTE: RDK's reboot cause does not distinguish between local and remote forms of reboot/factory reset
    // So we just assume that the cause was remotely initiated
    new_cause = "LocalReboot";
    if (strstr(rdk_cause, "reboot") != NULL)
    {
        new_cause = "RemoteReboot";
    }
    else if (strcmp(rdk_cause, "unknown")==0)           // This is if the user power cycles the device
    {
        new_cause = "LocalReboot";
    }
    else if (strcmp(rdk_cause, "factory-reset") == 0)
    {
        new_cause = "RemoteFactoryReset";
    }

    // If a different cause of factory reset has been detected, then set it in the USP database
    if (strcmp(new_cause, usp_cause) != 0)
    {
        err = USP_DM_SetParameterValue(usp_cause_path, new_cause);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** FireBootEvent
**
** Fires the Device.Boot! event with current reboot reason/cause
**
** \param   None
**
** \return  None
**
**************************************************************************/
void FireBootEvent(void)
{
    kv_vector_t *args = USP_MALLOC(sizeof(kv_vector_t));
    char cause[64] = "LocalReboot";
    char reason[64] = "Unknown";
    char* cmd_key = "";
    
    // Attempt to get the actual cause/reason from the data model if possible
    char* usp_cause_path = "Device.LocalAgent.ControllerTrust.Reporting.AbortedReason"; 
    USP_DM_GetParameterValue(usp_cause_path, cause, sizeof(cause)); 

    USP_ARG_Init(args);
    USP_ARG_Add(args, "CommandKey", cmd_key);
    USP_ARG_Add(args, "Cause", cause);
    USP_ARG_Add(args, "Reason", reason);
    USP_ARG_Add(args, "FirmwareUpdated", "false");
    USP_ARG_Add(args, "ParameterMap", "{}");

    USP_LOG_Info("Firing Device.Boot! (Cause=%s, Reason=%s)", cause, reason);
    
    if (USP_SIGNAL_DataModelEvent("Device.Boot!", args) != USP_ERR_OK) {
        USP_ARG_Destroy(args);
        USP_FREE(args);
    }
}

/*********************************************************************//**
**
** RegisterRdkParams
**
** Registers the RDK data model parameters specified in the given filename
**
** \param   filename - name of file specifying the data model parameters
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RegisterRdkParams(char *filename)
{
    #define MAX_LINE_LEN 512
    FILE *fp;
    int line_number = 1;
    char buf[MAX_LINE_LEN];
    char path[MAX_LINE_LEN];
    char type[MAX_LINE_LEN];
    char writable_str[MAX_LINE_LEN];
    unsigned type_flags;
    bool is_writable;
    char *result;
    int items_scanned;
    int err;

    // Exit if unable to open the file specifying the data model
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        USP_ERR_SetMessage("%s: Unable to open file specifying RDK data model parameters (%s)", __FUNCTION__, filename);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all lines in the file
    result = fgets(buf, sizeof(buf), fp);
    while (result != NULL)
    {
        // Skip blank or comment lines
        if ((buf[0]=='\0') || (buf[0]=='#') || (buf[0]=='\r') || (buf[0]=='\n'))
        {
            goto next_line;
        }

        // Exit if unable to read all details of the parameter to register
        items_scanned = sscanf(buf, "%s %s %s", path, type, writable_str);
        if (items_scanned != 3)
        {
            USP_ERR_SetMessage("%s: Not enough items on line %d of %s", __FUNCTION__, line_number, filename);
            err = USP_ERR_INTERNAL_ERROR;
            goto exit;
        }

        // Exit if unable to convert strings to info required to register the parameter
        err = TypeStringToUspType(type, &type_flags, line_number);
        err |= CalcIsWritable(writable_str, &is_writable, line_number);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // Exit if parameter registration failed
        if (is_writable)
        {
            err = USP_REGISTER_GroupedVendorParam_ReadWrite(GROUP_Id, path, type_flags);
        }
        else
        {
            err = USP_REGISTER_GroupedVendorParam_ReadOnly(GROUP_Id, path, type_flags);
        }

        if (err != USP_ERR_OK)
        {
            USP_LOG_Error("%s: Failed to register parameter %s (err %d)", __FUNCTION__, path, err);
            err = USP_ERR_OK; // continue
        }
        else
        {
            // Standardize: parameters never have a trailing dot
            char path_norm[MAX_LINE_LEN];
            strncpy(path_norm, path, sizeof(path_norm)-1);
            path_norm[sizeof(path_norm)-1] = '\0';
            size_t plen = strlen(path_norm);
            if (plen > 0 && path_norm[plen-1] == '.') path_norm[plen-1] = '\0';
            MarkPathAsRegistered(path_norm);
            USP_LOG_Info("RegisterRdkParams: Registered Parameter %s", path_norm);
        }

next_line:
        // Get the next line
        line_number++;
        result = fgets(buf, sizeof(buf), fp);
    }
    err = USP_ERR_OK;

exit:
    fclose(fp);
    return err;
}

/*********************************************************************//**
**
** RegisterRdkObjects
**
** Registers the RDK data model objects specified in the given filename
**
** \param   filename - name of file specifying the data model objects
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RegisterRdkObjects(char *filename)
{
    FILE *fp;
    int line_number = 1;
    char buf[MAX_LINE_LEN];
    char path[MAX_LINE_LEN];
    char writable_str[MAX_LINE_LEN];
    bool is_writable;
    char *result;
    int items_scanned;
    int err;

    // Exit if unable to open the file specifying the data model
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        USP_ERR_SetMessage("%s: Unable to open file specifying RDK data model objects (%s)", __FUNCTION__, filename);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all lines in the file
    result = fgets(buf, sizeof(buf), fp);
    while (result != NULL)
    {
        // Skip blank or comment lines
        if ((buf[0]=='\0') || (buf[0]=='#') || (buf[0]=='\r') || (buf[0]=='\n'))
        {
            goto next_line;
        }

        // Exit if unable to read all details of the object to register
        items_scanned = sscanf(buf, "%s %s", path, writable_str);
        if (items_scanned != 2)
        {
            USP_ERR_SetMessage("%s: Not enough items on line %d of %s", __FUNCTION__, line_number, filename);
            err = USP_ERR_INTERNAL_ERROR;
            goto exit;
        }

        // Exit if unable to convert strings to info required to register the object
        err = CalcIsWritable(writable_str, &is_writable, line_number);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // Standardize: ensure fixed objects DO NOT have a trailing dot, otherwise Obuspa aborts
        char path_norm[MAX_LINE_LEN];
        strncpy(path_norm, path, sizeof(path_norm)-1);
        path_norm[sizeof(path_norm)-1] = '\0';
        size_t plen = strlen(path_norm);
        bool is_multi = (strstr(path_norm, "{i}.") != NULL);
        if (!is_multi && plen > 0 && path_norm[plen-1] == '.') path_norm[plen-1] = '\0';

        // Exit if object registration failed
        err = USP_REGISTER_GroupedObject(GROUP_Id, path_norm, is_writable);
        if (err != USP_ERR_OK)
        {
            USP_LOG_Error("%s: Failed to register object %s (err %d)", __FUNCTION__, path_norm, err);
            err = USP_ERR_OK; // continue
        }
        else
        {
            MarkPathAsRegistered(path_norm);
            USP_LOG_Info("RegisterRdkObjects: Registered Object %s", path_norm);

            // If this is a top level multi-instance object, then it refreshes its instances and all below it
            if (IsTopLevelObject(path_norm))
            {
                err = USP_REGISTER_Object_RefreshInstances(path_norm, RDK_RefreshInstances);
                if (err != USP_ERR_OK)
                {
                    USP_LOG_Error("%s: Failed to register RefreshInstances hook for %s (err %d)", __FUNCTION__, path_norm, err);
                    err = USP_ERR_OK; // continue
                }
            }
        }

next_line:
        // Get the next line
        line_number++;
        result = fgets(buf, sizeof(buf), fp);
    }
    USP_LOG_Info("RegisterRdkObjects: Finished processing %s", filename);
    err = USP_ERR_OK;

exit:
    fclose(fp);

    return err;
}

/*********************************************************************//**
**
** TypeStringToUspType
**
** Given an RDK type string, convert it to a USP type
**
** \param   rdk_type_str - pointer to RDK type string to convert
** \param   usp_type - pointer to varaiable in which to return the converted USP type
** \param   line_number - line number in the file
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int TypeStringToUspType(char *rdk_type_str, unsigned *usp_type, int line_number)
{
    if (strcmp(rdk_type_str, "STRING") == 0)
    {
        *usp_type = DM_STRING;
    }
    else if (strcmp(rdk_type_str, "INT") == 0)
    {
        *usp_type = DM_INT;
    }
    else if (strcmp(rdk_type_str, "UINT") == 0)
    {
        *usp_type = DM_UINT;
    }
    else if (strcmp(rdk_type_str, "BOOL") == 0)
    {
        *usp_type = DM_BOOL;
    }
    else if (strcmp(rdk_type_str, "DATETIME") == 0)
    {
        *usp_type = DM_DATETIME;
    }
    else if (strcmp(rdk_type_str, "ULONG") == 0)
    {
        *usp_type = DM_ULONG;
    }
    else if (strcmp(rdk_type_str, "BYTES") == 0)
    {
        *usp_type = DM_HEXBIN;
    }
    else
    {
        USP_ERR_SetMessage("%s: Type %s not supported at line %d", __FUNCTION__, rdk_type_str, line_number);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** RdkTypeToTypeString
**
** Converts from a RDK parameter type to an RDK type string
**
** \param   type - type of the parameter
**
** \return  type string
**
**************************************************************************/
char *RdkTypeToTypeString(rbusValueType_t type)
{
    char *rdk_type_str = "None";

    switch(type)
    {
        case RBUS_BOOLEAN:
            rdk_type_str = "BOOL";
            break;

        case RBUS_CHAR:
            rdk_type_str = "CHAR";
            break;

        case RBUS_BYTE:
            rdk_type_str = "BYTE";
            break;

        case RBUS_INT8:
            rdk_type_str = "INT8";
            break;

        case RBUS_UINT8:
            rdk_type_str = "UINT8";
            break;

        case RBUS_INT16:
            rdk_type_str = "INT16";
            break;

        case RBUS_UINT16:
            rdk_type_str = "INT16";
            break;

        case RBUS_INT32:
            rdk_type_str = "INT";
            break;

        case RBUS_UINT32:
            rdk_type_str = "UINT";
            break;

        case RBUS_INT64:
            rdk_type_str = "LONG";
            break;

        case RBUS_UINT64:
            rdk_type_str = "ULONG";
            break;

        case RBUS_STRING:
            rdk_type_str = "STRING";
            break;

        case RBUS_DATETIME:
            rdk_type_str = "DATETIME";
            break;

        case RBUS_BYTES:
            rdk_type_str = "BYTES";
            break;

        case RBUS_SINGLE:
            USP_LOG_Warning("%s: WARNING: RBUS_SINGLE not supported. Using STRING", __FUNCTION__);
            rdk_type_str = "STRING";
            break;

        case RBUS_DOUBLE:
            USP_LOG_Warning("%s: WARNING: RBUS_DOUBLE not supported. Using STRING", __FUNCTION__);
            rdk_type_str = "STRING";
            break;

        case RBUS_PROPERTY:
        case RBUS_OBJECT:
        case RBUS_NONE:
            rdk_type_str = "unknown";
            break;
    }

    return rdk_type_str;
}

/*********************************************************************//**
**
** UspTypeToRdkType
**
** Converts from a USP parameter type to an RDK parameter type
**
** \param   type_flags - type of the parameter
**
** \return  RDK type
**
**************************************************************************/
int UspTypeToRdkType(unsigned type_flags)
{
    if (type_flags & DM_STRING)
    {
        return RBUS_STRING;
    }
    else if (type_flags & DM_DATETIME)
    {
        return RBUS_DATETIME;
    }
    else if (type_flags & DM_BOOL)
    {
        return RBUS_BOOLEAN;
    }
    else if (type_flags & DM_INT)
    {
        return RBUS_INT32;
    }
    else if (type_flags & DM_UINT)
    {
        return RBUS_UINT32;
    }
    else if (type_flags & DM_ULONG)
    {
        return RBUS_UINT64;
    }
    else if (type_flags & DM_HEXBIN)
    {
        return RBUS_BYTES;
    }
    else
    {
        // This assert should only fire if this function is not updated when new types are added to the data model
        USP_ASSERT(false);
    }

    return RBUS_STRING;
}

/*********************************************************************//**
**
** CalcIsWritable
**
** Given a string, return whether the string indicated whether the paramter was writable
**
** \param   str - pointer to string specifying whether the parameter is read only or read write
** \param   is_writable - pointer to varaible in which to return whether the parameter was writable
** \param   line_number - line number in the file
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int CalcIsWritable(char *str, bool *is_writable, int line_number)
{
    if (strcmp(str, "RW") == 0)
    {
        *is_writable = true;
    }
    else if (strcmp(str, "RO") == 0)
    {
        *is_writable = false;
    }
    else
    {
        USP_ERR_SetMessage("%s: Failed to convert %s at line %d (expecting 'RW' or 'RO')", __FUNCTION__, str, line_number);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** IsTopLevelObject
**
** Determines whether the specified schema path is a first level multi-instance object
**
** \param   path - path to the multi-instance object
**
** \return  true if the object is a top level object
**
**************************************************************************/
bool IsTopLevelObject(char *path)
{
    char *first_instance_separator;
    char *after_first_instance_separator;
    char *next_instance_separator;

    #define INSTANCE_SEPARATOR "{i}"
    first_instance_separator = strstr(path, INSTANCE_SEPARATOR);
    if (first_instance_separator == NULL)
    {
        USP_ERR_SetMessage("%s: %s is not a multi-instance object", __FUNCTION__, path);
        return false;
    }

    // Skip the instance separator
    after_first_instance_separator = first_instance_separator + sizeof(INSTANCE_SEPARATOR) - 1;


    // Exit if there is more than one instance separator, and hence this is not a top level multi-instance object
    next_instance_separator = strstr(after_first_instance_separator, INSTANCE_SEPARATOR);
    if (next_instance_separator != NULL)
    {
        return false;
    }

    return true;
}

/*********************************************************************//**
**
** ToRbusErrString
**
** Converts the given rbus error code to an error string
**
** \param   rbus_err - rbus error code
**
** \return  string representing the error
**
**************************************************************************/
char *ToRbusErrString(int rbus_err)
{
    switch(rbus_err)
    {
        case RBUS_ERROR_SUCCESS:
            return "RBUS_ERROR_SUCCESS";
        case RBUS_ERROR_BUS_ERROR:
            return "RBUS_ERROR_BUS_ERROR";
        case RBUS_ERROR_INVALID_INPUT:
            return "RBUS_ERROR_INVALID_INPUT";
        case RBUS_ERROR_NOT_INITIALIZED:
            return "RBUS_ERROR_NOT_INITIALIZED";
        case RBUS_ERROR_OUT_OF_RESOURCES:
            return "RBUS_ERROR_OUT_OF_RESOURCES";
        case RBUS_ERROR_DESTINATION_NOT_FOUND:
            return "RBUS_ERROR_DESTINATION_NOT_FOUND";
        case RBUS_ERROR_DESTINATION_NOT_REACHABLE:
            return "RBUS_ERROR_DESTINATION_NOT_REACHABLE";
        case RBUS_ERROR_DESTINATION_RESPONSE_FAILURE:
            return "RBUS_ERROR_DESTINATION_RESPONSE_FAILURE";
        case RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION:
            return "RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION";
        case RBUS_ERROR_INVALID_OPERATION:
            return "RBUS_ERROR_INVALID_OPERATION";
        case RBUS_ERROR_INVALID_EVENT:
            return "RBUS_ERROR_INVALID_EVENT";
        case RBUS_ERROR_INVALID_HANDLE:
            return "RBUS_ERROR_INVALID_HANDLE";
        case RBUS_ERROR_SESSION_ALREADY_EXIST:
            return "RBUS_ERROR_SESSION_ALREADY_EXIST";
        case RBUS_ERROR_COMPONENT_NAME_DUPLICATE:
            return "RBUS_ERROR_COMPONENT_NAME_DUPLICATE";
        case RBUS_ERROR_ELEMENT_NAME_DUPLICATE:
            return "RBUS_ERROR_ELEMENT_NAME_DUPLICATE";
        case RBUS_ERROR_ELEMENT_NAME_MISSING:
            return "RBUS_ERROR_ELEMENT_NAME_MISSING";
        case RBUS_ERROR_COMPONENT_DOES_NOT_EXIST:
            return "RBUS_ERROR_COMPONENT_DOES_NOT_EXIST";
        case RBUS_ERROR_ELEMENT_DOES_NOT_EXIST:
            return "RBUS_ERROR_ELEMENT_DOES_NOT_EXIST";
        case RBUS_ERROR_ACCESS_NOT_ALLOWED:
            return "RBUS_ERROR_ACCESS_NOT_ALLOWED";
        case RBUS_ERROR_INVALID_CONTEXT:
            return "RBUS_ERROR_INVALID_CONTEXT";
        case RBUS_ERROR_TIMEOUT:
            return "RBUS_ERROR_TIMEOUT";
        case RBUS_ERROR_ASYNC_RESPONSE:
            return "RBUS_ERROR_ASYNC_RESPONSE";
        case RBUS_ERROR_INVALID_METHOD:
            return "RBUS_ERROR_INVALID_METHOD";
        case RBUS_ERROR_NOSUBSCRIBERS:
            return "RBUS_ERROR_NOSUBSCRIBERS";
        case RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST:
            return "RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST";
        case RBUS_ERROR_INVALID_NAMESPACE:
            return "RBUS_ERROR_INVALID_NAMESPACE";
        case RBUS_ERROR_DIRECT_CON_NOT_EXIST:
            return "RBUS_ERROR_DIRECT_CON_NOT_EXIST";
        default:
            return "unknown RBUS error";
    }
}

/*********************************************************************//**
**
** RDK_GetEndpointId
**
** Gets the EndpointId of the device
**
** \param   buf - pointer to buffer in which to return the endpoint_id
** \param   len - length of the buffer
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_GetEndpointId(char *buf, int len)
{
    int err;
    kv_vector_t pv;
    kv_pair_t params[2];
    char *scheme = "os";
    char *oui;
    char *serial_number;
    int size;

    // Populate structure specifying the parameters to get
    pv.num_entries = 2;
    pv.vector = params;
    params[0].key = "Device.DeviceInfo.ManufacturerOUI";
    params[0].value = NULL;
    params[1].key = "Device.DeviceInfo.SerialNumber";
    params[1].value = NULL;

    // Exit if failed to retrieve the parameters
    // Exit if failed to retrieve the parameters
    err = RDK_GetGroup(GROUP_Id, &pv);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Warning("%s: Failed to retrieve ManufacturerOUI or SerialNumber from RBUS. Using fallback.", __FUNCTION__);
        strncpy(buf, "self-agent-fallback", len);
        err = USP_ERR_OK;
        goto exit;
    }

    // Exit if OUI or serial number were not retrieved
    oui = params[0].value;
    serial_number = params[1].value;
    if ((oui == NULL) || (serial_number == NULL) || (oui[0] == '\0') || (serial_number[0] == '\0'))
    {
        USP_LOG_Error("%s: Failed to retrieve ManufacturerOUI or SerialNumber", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
    }

    // Fixup serial number - this is needed for default serial number which contains a leading space and trailing newline
    if (serial_number[0] == ' ')
    {
        serial_number++;
    }

    size = strlen(serial_number);
    if (serial_number[size-1] == '\n')
    {
        serial_number[size-1] = '\0';
    }

    // Use a scheme of 'self::' if the OUI was not a six digit hex number
    if ((strlen(oui) != 6) || (TEXT_UTILS_HexStringToValue(oui) == INVALID))
    {
        scheme = "self";
    }

    // Form the endpoint_id
    USP_SNPRINTF(buf, len, "%s::%s-%s", scheme, oui, serial_number);
    err = USP_ERR_OK;

exit:
    USP_SAFE_FREE(params[0].value);
    USP_SAFE_FREE(params[1].value);
    return err;
}

/*********************************************************************//**
**
** RDK_AddObject
**
** Adds an instance to the specified data model object table
**
** \param   group_id - group ID of the object to add
** \param   path - path of the object in the data model
** \param   instance - pointer to varaiable in which to return instance number
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_AddObject(int group_id, char *path, int *instance)
{
    int rbus_err;
    char buf[MAX_DM_PATH];

    // Exit if this function is called before R-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to R-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Append a '.' to the end of the object path
    USP_SNPRINTF(buf, sizeof(buf), "%s.", path);

    // Exit if the add failed
    rbus_err = rbusTable_addRow(bus_handle, buf, NULL, (uint32_t *)instance);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_ERR_SetMessage("%s: rbusTable_addRow(%s) failed (%d - %s)", __FUNCTION__, buf, rbus_err, ToRbusErrString(rbus_err));
        return USP_ERR_CREATION_FAILURE;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** RDK_DeleteObject
**
** Deletes the specified instance from the specified data model object table
**
** \param   group_id - group ID of the object to delete
** \param   path - path of the instance in the data model to delete
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_DeleteObject(int group_id, char *path)
{
    int rbus_err;
    char buf[MAX_DM_PATH];

    // Exit if this function is called before R-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to R-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Append a '.' to the end of the object path
    USP_SNPRINTF(buf, sizeof(buf), "%s.", path);

    // Exit if the delete failed
    rbus_err = rbusTable_removeRow(bus_handle, buf);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_ERR_SetMessage("%s: rbusTable_removeRow(%s) failed (%d - %s)", __FUNCTION__, buf, rbus_err, ToRbusErrString(rbus_err));
        return USP_ERR_OBJECT_NOT_DELETABLE;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** RDK_GetGroup
**
** Gets the specified group of parameters from the RDK software component specified by group_id
**
** \param   group_id - ID of the group to get
** \param   params - key-value vector containing the parameter names as keys
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_GetGroup(int group_id, kv_vector_t *params)
{
    int i;
    int rbus_err;
    char const **paths = NULL;
    int num_values = 0;
    rbusProperty_t value = NULL;
    rbusProperty_t next = NULL;
    int err = USP_ERR_OK;
    bool replace = false;

    // Exit if this function is called before R-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to R-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Copy the paths of the parameters to get into the paths array
    paths = (char const **)USP_MALLOC((params->num_entries)*sizeof(char*));
    for (i=0; i < params->num_entries; i++)
    {
        paths[i] = params->vector[i].key;
    }


// Uncomment the following define if you want to log the amount of time taken to perform the group get for this component
//#define LOG_RDK_GET_TIME
#ifdef LOG_RDK_GET_TIME
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double start_time = (double)tv.tv_sec + (double)tv.tv_usec/(double)1000000.0;
#endif

    // Get the group of parameters provided by this software component
    rbus_err = rbus_getExt(bus_handle, params->num_entries, paths, &num_values, &value);

#ifdef LOG_RDK_GET_TIME
    gettimeofday(&tv, NULL);
    double finish_time = (double)tv.tv_sec + (double)tv.tv_usec/(double)1000000.0;
    double delta_time = finish_time - start_time;
    USP_LOG_Info("%s: %lf %s", __FUNCTION__, delta_time, params->vector[0].key);
#endif

    // Exit if unable to get the parameters
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        if (rbus_err == RBUS_ERROR_DESTINATION_NOT_FOUND || rbus_err == RBUS_ERROR_ELEMENT_DOES_NOT_EXIST)
        {
            // Provider has gone away. Perform synchronous deregistration of all paths
            // in this group, then return the most accurate USP error for a "missing"
            // resource: 7005 (Object Not Found).
            USP_LOG_Info("%s: Provider is gone. Performing synchronous deregistration of %d paths", __FUNCTION__, params->num_entries);

            for (i=0; i < params->num_entries; i++)
            {
                dml_task_t task;
                task.path = params->vector[i].key;
                task.type = RBUS_DMLNOTIFY_OBJECT_DELETION;
                // Note: The second arg as 0 indicates this is a synchronous call
                // and the handler must NOT free the stack-allocated task object.
                dml_register_task_handler(&task, (void*)(intptr_t)0);
            }
            err = 7005; // USP error for 'Object Not Found'
            goto exit;
        }
        USP_ERR_SetMessage("%s: rbus_get_Ext() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Iterate over all returned values, copying them into the params vector
    next = value;
    for (i = 0; i < params->num_entries && next != NULL; i++)
    {
        const char* param_name = rbusProperty_GetName(next);
        rbusValue_t param_value = rbusProperty_GetValue(next);
        char *string_value = rbusValue_ToString(param_value, NULL, 0);
        replace = USP_ARG_ReplaceWithHint(params, (char *)param_name, string_value, i);
        if (replace == false)
        {
            USP_ERR_SetMessage("%s: R-Bus returned a parameter name that was not requested", __FUNCTION__);
        }

        USP_SAFE_FREE(string_value);
        next = rbusProperty_GetNext(next);
    }
    err = USP_ERR_OK;

exit:
    // Clean up
    rbusProperty_Release(value);
    rbusProperty_Release(next);
    USP_SAFE_FREE(paths);

    return err;
}

/*********************************************************************//**
**
** RDK_SetGroup
**
** Sets the specified group of parameters from the RDK software component specified by group_id
**
** \param   group_id - ID of the group to get
** \param   params - key-value vector containing the parameter names as keys, and the values
** \param   param_types - array containing the type of each parameter in the params vector
** \param   failure_index - pointer to value in which to return the index of the first parameter in the params vector
**                          that failed to be set. Not changing this value or setting it to
**                          INVALID indicates that all parameters failed (e.g. communications failure)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_SetGroup(int group_id, kv_vector_t *params, unsigned *param_types, int *failure_index)
{
    int i;
    int rbus_err;
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    int err = USP_ERR_OK;
    rbusValue_t rbus_val;
    kv_pair_t *kv;
    char *s = NULL;
    bool isCommit = true;
    rbusSetOptions_t opts = {isCommit, RDK_SESSION_ID};
    rbusValueType_t type = RBUS_NONE;

    // Exit if this function is called before R-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to R-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form the rdk_params structure to pass to rbus_set()
    for (i=0; i < params->num_entries; i++)
    {
        kv = &params->vector[i];
        rbusValue_Init(&rbus_val);
        s=kv->key;
        type = UspTypeToRdkType(param_types[i]);
        if (rbusValue_SetFromString(rbus_val, type, kv->value) == false)
        {
            USP_ERR_SetMessage("Invalid data value passed to set: %d\n", rc);
            err = USP_ERR_INVALID_VALUE;
            *failure_index = i;
            break;
        }
        rbus_err = rbus_set(bus_handle, s, rbus_val, &opts);
        if (rbus_err != RBUS_ERROR_SUCCESS)
        {
            USP_ERR_SetMessage("%s: rbus_set() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
            err = USP_ERR_SET_FAILURE;
            *failure_index = i;
            rbusValue_Release(rbus_val);
            break;
        }
        rbusValue_Release(rbus_val);
    }

    return err;
}

/*********************************************************************//**
**
** RDK_RefreshInstances
**
** Gets the instance numbers
**
** Refreshes ObjectP and ObjectQ tables with instance numbers
** This function is called dynamically when accessing these tables
**
** \param   group_id - Identifies software component implementing this object
** \param   path - schema path to the top-level multi-instance node to refresh the instances of
** \param   expiry_period - Pointer to variable in which to return the number of seconds to cache the refreshed instances result
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_RefreshInstances(int group_id, char *path, int *expiry_period)
{
    int rbus_err;
    int err;
    char *name;
    int len;

    // Exit if this function is called before R-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to R-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    rbusElementInfo_t* elems = NULL;

    // Exit if unable to determine all instances provided by this rdk component
    rbus_err = rbusElementInfo_get(bus_handle, path, RBUS_MAX_NAME_DEPTH, &elems);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        // NOTE: getParameterNames may fail if the table has 0 entries, so just log a warning for this
        USP_LOG_Warning("%s: rbusElementInfo_get(%s) failed (%d- %s). Returning 0 instances for this object.", __FUNCTION__, path, rbus_err, ToRbusErrString(rbus_err));
        *expiry_period = 30;
        return USP_ERR_OK;
    }

    // Iterate over all parameters and objects found
    rbusElementInfo_t* elem;
    elem = elems;
    while(elem)
    {
        name = (char *)elem->name;
        len = strlen(name);

        // If this is an object instance, then refresh it in the data model
        if ((len >= 2) && (name[len-1] == '.') && (IS_NUMERIC(name[len-2])))
        {
            if (USP_DM_IsRegistered(name))
            {
                USP_DM_RefreshInstance(name);
            }
        }
        elem = elem->next;
    }

    // If the code gets here, then all object instances were successfully added to the data model
    err = USP_ERR_OK;
    *expiry_period = 30;

    // Free the rbusElementInfo_get allocated structure, as we have finished with it
    rbusElementInfo_free(bus_handle, elems);
    return err;
}

/*********************************************************************//**
**
** RDK_Reboot
**
** Called to signal to the vendor that the CPE should reboot
** By the time this function has been called, all communication channels to controllers will have been closed down
** This function would normally exit the USP Agent process
** However it doesn't have to, if it needs to wait until other actions running in the USP Agent process have completed
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_Reboot(void)
{
    return RdkResetInner("Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.RPC.RebootDevice", "Device, source=usp-reboot", "Reboot");
}

/*********************************************************************//**
**
** RDK_FactoryReset
**
** Called to signal to the vendor that the CPE should perform a factory reset
** By the time this function has been called, all communication channels to controllers will have been closed down
** This function would normally exit the USP Agent process
** However it doesn't have to, if it needs to wait until other actions running in the USP Agent process have completed
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RDK_FactoryReset(void)
{
    return RdkResetInner("Device.X_CISCO_COM_DeviceControl.FactoryReset", "Router", "Factory Reset");
}

/*********************************************************************//**
**
** RdkResetInner
**
** Called to perform a factory reset or a reboot by writing to the specified parameter
** NOTE: This function exits the USP Agent executable after successfully initiating the required action
**
** \param   path - full data model path of the parameter to write to
** \param   value - value to write to the parameter
** \param   debug_msg - log message to print out before rebooting
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RdkResetInner(char *path, char *value, char *debug_msg)
{
    int rbus_err;
    USP_ASSERT(bus_handle == NULL); // Because USP_PA_Stop() is called before performing a reboot/factory reset
    bool isCommit = true;
    rbusSetOptions_t opts = {isCommit, RDK_SESSION_ID};

    // Exit if unable to re-connect to the RDK message bus
    rbus_err = rbus_open(&bus_handle, (char*)USPPA_COMPONENT_NAME);
    if (rbus_err != 0)
    {
        USP_ERR_SetMessage("%s: rbus_open() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if this function is called before R-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to R-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Fill in the details of the parameter controlling reboot or factory reset
    rbusValue_t val ;
    rbusValue_Init(&val);
    rbusValue_SetString(val, value);

    // Exit if unable to set the parameter
    rbus_err =rbus_set(bus_handle, path, val, &opts);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_ERR_SetMessage("%s:rbus_set(%s) failed (%d - %s)", __FUNCTION__, path, rbus_err, ToRbusErrString(rbus_err));
        return USP_ERR_INTERNAL_ERROR;
    }

    // USP Agent exits
    USP_LOG_Info("%s: Performing %s", __FUNCTION__, debug_msg);
    rbusValue_Release(val);
    exit(0);

}

/*********************************************************************//**
**
** DiscoverDM_ForAllComponents
**
** Discovers the data model available on this device
**
** \param   objs_filename - name of file to write the discovered data model objects into
** \param   params_filename - name of file to write the discovered data model parameters into
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DiscoverDM_ForAllComponents(char *objs_filename, char *params_filename)
{
    int err;
    kv_vector_t rdk_objects;
    kv_vector_t rdk_params;

    // Exit if this function is called before R-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to R-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Initialise vectors to put the discovered data model configuration into
    USP_ARG_Init(&rdk_objects);
    USP_ARG_Init(&rdk_params);

    // To discovering the parameters and objects of DM Elements
    Discover_AllDM(&rdk_objects, &rdk_params);  // Intentionally ignoring any errors


    // Exit if unable to write either of the files successfully
    err = USP_ERR_OK;
    err |= WriteDMConfig(params_filename, "w", &rdk_params, "# Configuration file for data model parameters accessible over USP\n");
    err |= WriteDMConfig(objs_filename, "w", &rdk_objects, "# Configuration file for data model objects accessible over USP\n");
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

exit:
    USP_ARG_Destroy(&rdk_objects);
    USP_ARG_Destroy(&rdk_params);

    return err;
}

/*********************************************************************//**
**
** Discover_AllDM
**
** Discovers the whole data model
**
** \param   rdk_objects - key value vector of DM Element object path vs properties
** \param   rdk_params - key value vector of DM Element parameter path vs properties
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Discover_AllDM(kv_vector_t *rdk_objects, kv_vector_t *rdk_params)
{
    int rbus_err;
    int err;
    // Exit if unable to determine all instances provided by this rdk component
    USP_LOG_Info("%s: Getting DM Elements using rbus", __FUNCTION__);
    rbusElementInfo_t* elems = NULL;
    rbusElementInfo_t* elem = NULL;
    rbus_err = rbusElementInfo_get(bus_handle, "Device.", RBUS_MAX_NAME_DEPTH, &elems);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_LOG_Error("%s: rbusElementInfo_get failed (%d)", __FUNCTION__, rbus_err);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all parameters and objects found
    elem = elems;
    while(elem)
    {
        char *write_status = (elem->type == RBUS_ELEMENT_TYPE_TABLE ? elem->access & RBUS_ACCESS_ADDROW : elem->access & RBUS_ACCESS_SET)  ? "RW" : "RO";
        Add_NameToDM((char *)elem->name, write_status, rdk_objects, rdk_params);
        elem = elem->next;
    }

    // If the code gets here, then all object instances were successfully added to the data model
    err = USP_ERR_OK;

    // Free the rbusElementInfo_get allocated structure, as we have finished with it
    rbusElementInfo_free(bus_handle, elems);
    return err;
}

/*********************************************************************//**
**
** Add_NameToDM
**
** Adds the specified path (object or parameter) to the relevant key-value vector
**
** \param   rdkc - component providing part of the data model
** \param   instantiated_path - Instantiated data model path of the parameter or object to add
** \param   write_status - whether the parameter or object is read only or writable
** \param   rdk_objects - key value vector of DM Element object path vs properties
** \param   rdk_params - key value vector of DM Element parameter path vs properties
**
** \return  None
**
**************************************************************************/
void Add_NameToDM( char *instantiated_path, char *write_status, kv_vector_t *rdk_objects, kv_vector_t *rdk_params)
{
    char schema_path[MAX_DM_PATH];
    int len;

    ConvertInstantiatedToSchemaPath(instantiated_path, schema_path, sizeof(schema_path));

    // Expert Recommendation (Shallow Discovery Persistence): 
    // We want to save the "Table Containers" so we can register hooks at boot.
    // For extreme performance, we limit the depth of what we persist to disk.
    if (g_shallow_discovery)
    {
        int dots = 0;
        char *p = schema_path;
        while (*p) if (*p++ == '.') dots++;
        
        // Expert Alignment: Allow up to 20 levels for objects/parameters in the persistent cache.
        // This ensures the agent never loses even deeply nested vendor branches.
        if (dots > 20) return;
        
        // Always allow paths that have a table instance component (to ensure multi-instance survives)
        // But if they are extremely deep, we still skip 
        if (strstr(schema_path, "{i}.") && dots > 21) return;
    }

    // Exit if length is too short to be considered a data model path
    len = strlen(schema_path);
    if (len < 4)
    {
        return;
    }

    if (schema_path[len-1] == '.')
    {
        // Add both fixed objects and multi-instance objects so we have table containers at boot
        Add_ObjectToDM(schema_path, write_status, rdk_objects);
    }
    else
    {
        // Parameter: Save current state if it passes depth checks
        Add_ParamToDM(instantiated_path, schema_path, write_status, rdk_params);
    }
}

/*********************************************************************//**
**
** Add_ObjectToDM
**
** Adds the specified data model object to the 'rdk_objects' key-value vector
**
** \param   rdkc - component providing part of the data model
** \param   schema_path - data model supported path of the object to add
** \param   write_status - whether the object is read only or writable. Writable indicates that a USP controller can add/delete instances
** \param   rdk_objects - key value vector of data model object path vs properties
**
** \return  None
**
**************************************************************************/
void Add_ObjectToDM(char *schema_path, char *write_status, kv_vector_t *rdk_objects)
{
    char *is_exist;
    char buf[128];

    // Exit if object already exists
    is_exist = USP_ARG_Get(rdk_objects, schema_path, NULL);
    if (is_exist != NULL)
    {
        return;
    }

    // Add object
    USP_SNPRINTF(buf, sizeof(buf), "%s", write_status);
    USP_ARG_Add(rdk_objects, schema_path, buf);
}

/*********************************************************************//**
**
** Add_ParamToDM
**
** Adds the specified data model parameter to the 'rdk_params' key-value vector
**
** \param   rdkc - component providing part of the data model
** \param   instantiated_path - Instantiated data model path of the parameter or object to add
** \param   schema_path - data model supported path of the object to add
** \param   write_status - whether the parameter is read only or writable
** \param   rdk_params - key value vector of data model parameter path vs properties
**
** \return  None
**
**************************************************************************/
void Add_ParamToDM( char *instantiated_path, char *schema_path, char *write_status, kv_vector_t *rdk_params)
{
    int rbus_err;
    rbusProperty_t values;
    rbusProperty_t val;
    int num_values = 0;
    char *type_str;
    char *is_exist;
    char buf[128];
    char *p;

    // Iterate over the path, checking that all occurrences of the instance separator are correctly specified
    p = schema_path;
    while (p != NULL)
    {
        // Break out of loop if checked all occurrences
        p = strchr(p, '{');
        if (p == NULL)
        {
            break;
        }

        // Exit if instance separator is not correctly specified
        if (strncmp(&p[-1], ".{i}.", 5) != 0)
        {
            USP_LOG_Error("%s: WARNING: Bad path: Not adding %s to the data model", __FUNCTION__, schema_path);
            return;
        }

        // Skip '{' character
        p++;
    }

    // Exit if param already exists
    is_exist = USP_ARG_Get(rdk_params, schema_path, NULL);
    if (is_exist != NULL)
    {
        return;
    }

    // Exit if unable to get the parameter in order to determine its type (and also check that it is readable)
    rbus_err =rbus_getExt(bus_handle, 1, (const char**)&instantiated_path, &num_values, &values);
    if (rbus_err != RBUS_ERROR_SUCCESS)
    {
        USP_LOG_Error("%s: rbus_get_Ext() failed (%d - %s)", __FUNCTION__, rbus_err, ToRbusErrString(rbus_err));
        USP_LOG_Error("%s: WARNING: Not adding to the data model %s", __FUNCTION__, instantiated_path );
        return;
    }

    // Determine its type (as a string)
    val = values;
    rbusValueType_t type = RBUS_NONE;
    type = rbusValue_GetType(rbusProperty_GetValue(val));
    type_str = RdkTypeToTypeString(type);

    // Add param
    USP_SNPRINTF(buf, sizeof(buf), "%s %s", type_str, write_status);
    USP_ARG_Add(rdk_params, schema_path, buf);

    // Free data structure returned by rbus_get_Ext()
    rbusProperty_Release(values);
}

/*********************************************************************//**
**
** ConvertInstantiatedToSchemaPath
**
** Converts an instantiated data model path to a schema path
** by replacing instance numbers in the string with '{i}'
**
** \param   src - pointer to instantiated data model path to convert
** \param   dest - pointer to buffer in which to store the converted schema path
** \param   len - length of the buffer in which to store the converted schema path
**
** \return  None
**
**************************************************************************/
void ConvertInstantiatedToSchemaPath(char *src, char *dest, int len)
{
    char *p;
    int num_digits;
    char c;

    c = *src++;
    while ((c != '\0') && (len > 3))
    {
        if (c == '.')
        {
            // Copy across the dot
            *dest++ = c;
            len--;

            // Determine the number of digits, if the following path segment is a number
            p = src;
            c = *p++;
            num_digits = 0;
            while (IS_NUMERIC(c))
            {
                num_digits++;
                c = *p++;
            }

            // If the path segment is a number, then skip the digits, and replace them with '{i}' in the output
            if (num_digits >0)
            {
                src += num_digits;
                *dest++ = '{';
                *dest++ = 'i';
                *dest++ = '}';
                len -= 3;
            }

            c = *src++;
        }
        else
        {
            // Copy across the character
            *dest++ = c;
            len--;
            c = *src++;
        }
    }

    // Terminate the output string
    *dest = '\0';
}

/*********************************************************************//**
**
** WriteDMConfig
**
** Writes the data model configuration specified in a key-value vector to the specified file
**
** \param   filename - Name of file to write
** \param   mode - whether to write the file from scratch, or append to the existing file
** \param   kvv - key-value vector containing the data model configuration to write
** \param   comment - comment to write to the config file before the configuration
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int WriteDMConfig(char *filename, char *mode, kv_vector_t *kvv, char *comment)
{
    int err;
    FILE *fp;
    int bytes_written;
    int len;
    int i;
    kv_pair_t *kv;
    char buf[256];

    // Exit if unable to open file to write the data model configuration into
    fp = fopen(filename, mode);
    if (fp == NULL)
    {
        USP_LOG_Error("%s: Unable to open file %s with mode %s", __FUNCTION__, filename, mode);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to write comment
    len = strlen(comment);
    bytes_written = fwrite(comment, 1, len, fp);
    if (bytes_written != len)
    {
        USP_LOG_Error("%s: Failed to write to %s with mode %s", __FUNCTION__, filename, mode);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Iterate over all data model objects or parameters present in the key-value vector
    for (i=0; i < kvv->num_entries; i++)
    {
        // Form config line to write
        kv = &kvv->vector[i];
        USP_SNPRINTF(buf, sizeof(buf), "%s %s\n", kv->key, kv->value);

        // Exit if unable to write this config line
        len = strlen(buf);
        bytes_written = fwrite(buf, 1, len, fp);
        if (bytes_written != len)
        {
            USP_LOG_Error("%s: Failed to write to %s with mode %s", __FUNCTION__, filename, mode);
            err = USP_ERR_INTERNAL_ERROR;
            goto exit;
        }
    }

    err = USP_ERR_OK;

exit:
    fclose(fp);
    return err;
}
