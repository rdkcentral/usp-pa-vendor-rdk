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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <ccsp_message_bus.h>
#include <ccsp_base_api.h>
#include <dslh_definitions_database.h>

#include "common_defs.h"
#include "usp_api.h"
#include "text_utils.h"


//-------------------------------------------------------------------------------------------------
// Handle for connection to DBus
static void *bus_handle = NULL;

//-------------------------------------------------------------------------------------------------
// Names of components on DBus
#define CCSP_USPPA_AGENT_PA_SUBSYSTEM           "eRT."
#define USPPA_COMPONENT_NAME                    "com.bbf.ccsp.usppa"
#define CONF_FILENAME                           "/tmp/ccsp_msg.cfg"
#define FULL_COMPONENT_REGISTRAR_NAME           CCSP_USPPA_AGENT_PA_SUBSYSTEM CCSP_DBUS_INTERFACE_CR

//-------------------------------------------------------------------------------------------------
// Array containing RDK components which implement the data model
typedef struct
{
    char *group_name;       // short name, used in the text files specifying the data model to identify the group
    char *component_name;
    char *dbus_path;
} rdk_component_t;

static rdk_component_t *rdk_components = NULL;
static int num_rdk_components = 0;

//-------------------------------------------------------------------------------------------------
// Session ID for RDK component database transactions associated with set, add and delete
// NOTE: The RDK software components don't accept any value other than 0, and do not support the CcspBaseIf_requestSessionID() API
#define RDK_SESSION_ID 0

//-------------------------------------------------------------------------------------------------
// Write ID for RDK component database transactions associated with set, add and delete
#define CCSP_USP_WRITE_ID                 DSLH_MPA_ACCESS_CONTROL_ACS

//-------------------------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void WaitForRdkComponentsReady(void);
int FixupRebootCause(void);
int RegisterRdkComponents(char *filename);
int RegisterRdkParams(char *filename);
int RegisterRdkObjects(char *filename);
int TypeStringToUspType(char *rdk_type_str, unsigned *usp_type, int line_number);
char *RdkTypeToTypeString(enum dataType_e type);
int UspTypeToRdkType(unsigned param_type);
int CalcIsWritable(char *str, bool *is_writable, int line_number);
int CalcGroupId(char *group_name);
bool IsTopLevelObject(char *path);
char *ToCcspErrString(int ccsp_err);
int RDK_GetEndpointId(char *buf, int len);
int RDK_AddObject(int group_id, char *path, int *instance);
int RDK_DeleteObject(int group_id, char *path);
int RDK_GetGroup(int group_id, kv_vector_t *params);
int RDK_SetGroup(int group_id, kv_vector_t *params, unsigned *param_types, int *failure_index);
int RDK_RefreshInstances(int group_id, char *path, int *expiry_period);
int RDK_Reboot(void);
int RDK_FactoryReset(void);
int RdkResetInner(char *group_name, char *path, char *value, char *debug_msg);
int DiscoverDM_Components(char *comps_filename);
int DiscoverDM_ForAllComponents(char *objs_filename, char *params_filename);
int DiscoverDM_ForComponent(rdk_component_t *rdkc, kv_vector_t *rdk_objects, kv_vector_t *rdk_params);
void Add_NameToDM(rdk_component_t *rdkc, char *instantiated_path, char *write_status, kv_vector_t *rdk_objects, kv_vector_t *rdk_params);
void Add_ObjectToDM(rdk_component_t *rdkc, char *schema_path, char *write_status, kv_vector_t *rdk_objects);
void Add_ParamToDM(rdk_component_t *rdkc, char *instantiated_path, char *schema_path, char *write_status, kv_vector_t *rdk_params);
void ConvertInstantiatedToSchemaPath(char *src, char *dest, int len);
void AddMissingObjs(kv_vector_t *rdk_objects, kv_vector_t *rdk_params, kv_vector_t *missing_objs);
int WriteDMConfig(char *filename, char *mode, kv_vector_t *kvv, char *comment);
void *rdk_malloc(size_t size);
void rdk_free(void *ptr);

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
    int i;
    int err;
    vendor_hook_cb_t core_callbacks;
    int ccsp_err;
    struct stat info;

    // Exit if unable to connect to the RDK message bus
    // NOTE: We do this here, rather than in VENDOR_Start() because the SerialNumber, ManufacturerOUI and SoftwareVersion are cached before CCSP_USP_PA_Start() is called
    ccsp_err = CCSP_Message_Bus_Init((char*)USPPA_COMPONENT_NAME, (char*)CONF_FILENAME, &bus_handle, rdk_malloc, rdk_free);
    if (ccsp_err != 0)
    {
        USP_ERR_SetMessage("%s: CCSP_Message_Bus_Init() failed (%d - %s)", __FUNCTION__, ccsp_err, ToCcspErrString(ccsp_err));
        return USP_ERR_INTERNAL_ERROR;
    }

    // Waits until all RDK components have registered with the system
    WaitForRdkComponentsReady();

    // Create the data model component config file, if it does not already exist
    #define DM_COMPS_FILE  "/etc/usp-pa/usp_dm_comps.conf"
    if (stat(DM_COMPS_FILE, &info) != 0)
    {
        USP_LOG_Info("%s: Regenerating missing USP data model component file. This may take a while.", __FUNCTION__);
        err = DiscoverDM_Components(DM_COMPS_FILE);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }

    // Exit if unable to register the RDK data model provider components
    err = RegisterRdkComponents(DM_COMPS_FILE);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Create the data model config files, if they do not already exist
    #define DM_OBJS_FILE   "/etc/usp-pa/usp_dm_objs.conf"
    #define DM_PARAMS_FILE "/etc/usp-pa/usp_dm_params.conf"
    if ((stat(DM_COMPS_FILE, &info) != 0) || (stat(DM_OBJS_FILE, &info) != 0) || (stat(DM_PARAMS_FILE, &info) != 0))
    {
        // Discover the data model objects and parameters
        USP_LOG_Info("%s: Regenerating missing USP data model config files. This may take a while.", __FUNCTION__);
        err = DiscoverDM_ForAllComponents(DM_OBJS_FILE, DM_PARAMS_FILE);
        if (err != USP_ERR_OK)
        {
            return err;
        }
        USP_LOG_Info("%s: Written USP data model config files. Starting normally.", __FUNCTION__);
    }

    // Exit if unable to register RDK data model objects
    err = RegisterRdkObjects(DM_OBJS_FILE);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to register RDK data model parameters
    err = RegisterRdkParams(DM_PARAMS_FILE);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to register group get and set vendor hooks for all RDK software components
    for (i=0; i<num_rdk_components; i++)
    {
        err = USP_REGISTER_GroupVendorHooks(i, RDK_GetGroup, RDK_SetGroup, RDK_AddObject, RDK_DeleteObject);
        if (err != USP_ERR_OK)
        {
            return err;
        }
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
        return err;
    }

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
    // Disconnect from the RDK bus
    if (bus_handle != NULL)
    {
        CCSP_Message_Bus_Exit(bus_handle);
        bus_handle = NULL;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** WaitForRdkComponentsReady
**
** Waits until the pam component is ready,
** so that we don't attempt to query any of the parameters provided by it, until it is
**
** \param   None
**
** \return  None
**
**************************************************************************/
void WaitForRdkComponentsReady(void)
{
    int ccsp_err = CCSP_ERR_NOT_CONNECT;
    char *paths[1] = { "Device.DeviceInfo.SerialNumber" };
    int num_values = 0;
    parameterValStruct_t **values = NULL;
    int count = 0;
  
    while (ccsp_err != CCSP_SUCCESS)
    {
        // Wait until pam component is running
        ccsp_err = CcspBaseIf_getParameterValues(bus_handle, "eRT.com.cisco.spvtg.ccsp.pam", "/com/cisco/spvtg/ccsp/pam", paths, NUM_ELEM(paths), &num_values, &values);
        if (ccsp_err != CCSP_SUCCESS)
        {
            USP_ERR_SetMessage("%s: CcspBaseIf_getParameterValues() failed (%d - %s).", __FUNCTION__, ccsp_err, ToCcspErrString(ccsp_err));

            // Wait a while, and try again, if the pam component is not running yet
            #define SYSTEM_READY_POLL_PERIOD 10
            USP_ERR_SetMessage("%s: Waiting %d seconds for RDK system to be ready (total_wait=%d seconds)", __FUNCTION__, SYSTEM_READY_POLL_PERIOD, count);
            sleep(SYSTEM_READY_POLL_PERIOD);
            count += SYSTEM_READY_POLL_PERIOD;
        }
    }

    // Free the values read
    free_parameterValStruct_t(bus_handle, num_values, values);
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
    err = USP_DM_GetParameterValue("Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason", rdk_cause, sizeof(rdk_cause));
    if (err != USP_ERR_OK)
    {
        return err;
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
** RegisterRdkComponents
**
** Registers the RDK data model provider components into rdk_components vector
**
** \param   filename - name of file specifying the provider components
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RegisterRdkComponents(char *filename)
{
    #define MAX_LINE_LEN 512
    FILE *fp;
    int line_number = 1;
    char buf[MAX_LINE_LEN];
    char group_name[MAX_LINE_LEN];
    char component_name[MAX_LINE_LEN];
    char dbus_path[MAX_LINE_LEN];
    rdk_component_t *rdkc;
    char *result;
    int items_scanned;
    int err;

    // Exit if unable to open the file specifying the provider components
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        USP_ERR_SetMessage("%s: Unable to open file specifying RDK data model provider components (%s)", __FUNCTION__, filename);
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

        // Exit if unable to read all details of the component to register
        items_scanned = sscanf(buf, "%s %s %s", group_name, component_name, dbus_path);
        if (items_scanned != 3)
        {
            USP_ERR_SetMessage("%s: Not enough items on line %d of %s", __FUNCTION__, line_number, filename);
            err = USP_ERR_INTERNAL_ERROR;
            goto exit;
        }

        // Add this component to the end of the rdk_components vector
        num_rdk_components++;        
        rdk_components = USP_REALLOC(rdk_components, num_rdk_components*sizeof(rdk_component_t));
        rdkc = &rdk_components[num_rdk_components-1];
        rdkc->group_name = USP_STRDUP(group_name);
        rdkc->component_name = USP_STRDUP(component_name);
        rdkc->dbus_path = USP_STRDUP(dbus_path);

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
    char group_name[MAX_LINE_LEN];
    char type[MAX_LINE_LEN];
    char writable_str[MAX_LINE_LEN];
    unsigned type_flags;
    int group_id;
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
        items_scanned = sscanf(buf, "%s %s %s %s", path, group_name, type, writable_str);
        if (items_scanned != 4)
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

        // Exit if unable to determine the group_id of the parameter
        group_id = CalcGroupId(group_name);
        if (group_id == INVALID)
        {
            err = USP_ERR_INTERNAL_ERROR;
            goto exit;
        }

        // Exit if parameter registration failed
        if (is_writable)
        {
            err = USP_REGISTER_GroupedVendorParam_ReadWrite(group_id, path, type_flags);
        }
        else
        {
            err = USP_REGISTER_GroupedVendorParam_ReadOnly(group_id, path, type_flags);
        }

        if (err != USP_ERR_OK)
        {
            goto exit;
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
    char group_name[MAX_LINE_LEN];
    char writable_str[MAX_LINE_LEN];
    int group_id;
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
        items_scanned = sscanf(buf, "%s %s %s", path, group_name, writable_str);
        if (items_scanned != 3)
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

        // Exit if unable to determine the group_id of the object
        group_id = CalcGroupId(group_name);
        if (group_id == INVALID)
        {
            err = USP_ERR_INTERNAL_ERROR;
            goto exit;
        }

        // Exit if object registration failed
        err = USP_REGISTER_GroupedObject(group_id, path, is_writable);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // If this is a top level multi-instance object, then it refreshes its instances and all below it
        if (IsTopLevelObject(path))
        {
            err = USP_REGISTER_Object_RefreshInstances(path, RDK_RefreshInstances);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }
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
char *RdkTypeToTypeString(enum dataType_e type)
{
    char *rdk_type_str;

    switch(type)
    {
        case ccsp_string:
            rdk_type_str = "STRING";
            break;

        case ccsp_int:
        case ccsp_long:
            rdk_type_str = "INT";
            break;

        case ccsp_unsignedInt:
            rdk_type_str = "UINT";
            break;

        case ccsp_boolean:
            rdk_type_str = "BOOL";
            break;

        case ccsp_dateTime:
            rdk_type_str = "DATETIME";
            break;

        case ccsp_base64:
            rdk_type_str = "STRING";
            break;

        case ccsp_unsignedLong:
            rdk_type_str = "ULONG";
            break;

        case ccsp_float:
            USP_LOG_Warning("%s: WARNING: ccsp_float not supported. Using STRING", __FUNCTION__);
            rdk_type_str = "STRING";
            break;

        case ccsp_double:
            USP_LOG_Warning("%s: WARNING: ccsp_double not supported. Using STRING", __FUNCTION__);
            rdk_type_str = "STRING";
            break;

        case ccsp_byte:
            rdk_type_str = "UINT";
            break;

        default:
        case ccsp_none:
            rdk_type_str = "STRING";
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
        return ccsp_string;
    }
    else if (type_flags & DM_DATETIME)
    {
        return ccsp_dateTime;
    }
    else if (type_flags & DM_BOOL)
    {
        return ccsp_boolean;
    }
    else if (type_flags & DM_INT)
    {
        return ccsp_int;
    }
    else if (type_flags & DM_UINT)
    {
        return ccsp_unsignedInt;
    }
    else if (type_flags & DM_ULONG)
    {
        return ccsp_unsignedLong;
    }
    else
    {
        // This assert should only fire if this function is not updated when new types are added to the data model
        USP_ASSERT(false);
    }

    return ccsp_string;
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
** CalcGroupId
**
** Given a group_name, determine the group_id
**
** \param   group_name - name of software component that owns the parameter
**
** \return  group_id with the specified group name or INVALID if none found
**
**************************************************************************/
int CalcGroupId(char *group_name)
{
    int i;
    rdk_component_t *rdkc;

    // Iterate over all RDK components, seeing if this matches one
    for (i=0; i<num_rdk_components; i++)
    {
        rdkc = &rdk_components[i];
        if (strcmp(rdkc->group_name, group_name)==0)
        {
            return i;
        }
    }

    // If the code gets here, then no match was found
    USP_ERR_SetMessage("%s: RDK Functional component '%s' not found.", __FUNCTION__, group_name);
    return INVALID;
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
** ToCcspErrString
**
** Converts the given CCSP error code to an error string
**
** \param   ccsp_err - ccsp error code
**
** \return  string representing the error
**
**************************************************************************/
char *ToCcspErrString(int ccsp_err)
{
    char *s;

    switch(ccsp_err)
    {
        case CCSP_SUCCESS:
            s = "CCSP_SUCCESS";

        case CCSP_ERR_MEMORY_ALLOC_FAIL:
            s = "CCSP_ERR_MEMORY_ALLOC_FAIL";
            break;

        case CCSP_FAILURE:
            s = "CCSP_FAILURE";
            break;

        case CCSP_ERR_NOT_CONNECT:
            s = "CCSP_ERR_NOT_CONNECT - can't connect to daemon";
            break;

        case CCSP_ERR_TIMEOUT:
            s = "CCSP_ERR_TIMEOUT";
            break;

        case CCSP_ERR_NOT_EXIST:
            s = "CCSP_ERR_NOT_EXIST - remote not exist ";
            break;

        case CCSP_ERR_NOT_SUPPORT:
            s = "CCSP_ERR_NOT_SUPPORT - remote can't support this API";
            break;

        case CCSP_ERR_METHOD_NOT_SUPPORTED:
            s = "CCSP_ERR_METHOD_NOT_SUPPORTED";
            break;

        case CCSP_ERR_REQUEST_REJECTED:
            s = "CCSP_ERR_REQUEST_REJECTED";
            break;

        case CCSP_ERR_INTERNAL_ERROR:
            s = "CCSP_ERR_INTERNAL_ERROR";
            break;

        case CCSP_ERR_INVALID_ARGUMENTS:
            s = "CCSP_ERR_INVALID_ARGUMENTS";
            break;

        case CCSP_ERR_RESOURCE_EXCEEDED:
            s = "CCSP_ERR_RESOURCE_EXCEEDED";
            break;

        case CCSP_ERR_INVALID_PARAMETER_NAME:
            s = "CCSP_ERR_INVALID_PARAMETER_NAME";
            break;

        case CCSP_ERR_INVALID_PARAMETER_TYPE:
            s = "CCSP_ERR_INVALID_PARAMETER_TYPE";
            break;

        case CCSP_ERR_INVALID_PARAMETER_VALUE:
            s = "CCSP_ERR_INVALID_PARAMETER_VALUE";
            break;

        case CCSP_ERR_NOT_WRITABLE:
            s = "CCSP_ERR_NOT_WRITABLE";
            break;

        case CCSP_ERR_SETATTRIBUTE_REJECTED:
            s = "CCSP_ERR_SETATTRIBUTE_REJECTED";
            break;

        case CCSP_ERR_FILE_TRANSFER_FAILURE:
            s = "CCSP_ERR_FILE_TRANSFER_FAILURE";
            break;

        case CCSP_ERR_UPLOAD_FAILURE:
            s = "CCSP_ERR_UPLOAD_FAILURE";
            break;

        case CCSP_ERR_FILE_TRANSFER_AUTH_FAILURE:
            s = "CCSP_ERR_FILE_TRANSFER_AUTH_FAILURE";
            break;

        case CCSP_ERR_UNSUPPORTED_PROTOCOL:
            s = "CCSP_ERR_UNSUPPORTED_PROTOCOL";
            break;

        case CCSP_ERR_UNABLE_TO_JOIN_MULTICAST:
            s = "CCSP_ERR_UNABLE_TO_JOIN_MULTICAST";
            break;

        case CCSP_ERR_UNABLE_TO_CONTACT_FILE_SERVER:
            s = "CCSP_ERR_UNABLE_TO_CONTACT_FILE_SERVER";
            break;

        case CCSP_ERR_UNABLE_TO_ACCESS_FILE:
            s = "CCSP_ERR_UNABLE_TO_ACCESS_FILE";
            break;

        case CCSP_ERR_UNABLE_TO_COMPLETE_DOWNLOAD:
            s = "CCSP_ERR_UNABLE_TO_COMPLETE_DOWNLOAD";
            break;

        case CCSP_ERR_FILE_CORRUPTED_OR_UNUSABLE:
            s = "CCSP_ERR_FILE_CORRUPTED_OR_UNUSABLE";
            break;

        case CCSP_ERR_FILE_AUTH_FAILURE:
            s = "CCSP_ERR_FILE_AUTH_FAILURE";
            break;

        case CCSP_ERR_UNABLE_TO_COMPLETE_ONTIME:
            s = "CCSP_ERR_UNABLE_TO_COMPLETE_ONTIME";
            break;

        case CCSP_ERR_CANCELATION_NOT_PERMITTED:
            s = "CCSP_ERR_CANCELATION_NOT_PERMITTED";
            break;

        case CCSP_ERR_INVALID_UUID_FORMAT:
            s = "CCSP_ERR_INVALID_UUID_FORMAT";
            break;

        case CCSP_ERR_UNKNOWN_EE:
            s = "CCSP_ERR_UNKNOWN_EE";
            break;

        case CCSP_ERR_DISABLED_EE:
            s = "CCSP_ERR_DISABLED_EE";
            break;

        case CCSP_ERR_DU_EE_MISMATCH:
            s = "CCSP_ERR_DU_EE_MISMATCH";
            break;

        case CCSP_ERR_DUPLICATE_DU:
            s = "CCSP_ERR_DUPLICATE_DU";
            break;

        case CCSP_ERR_SYSTEM_RES_EXCEEDED:
            s = "CCSP_ERR_SYSTEM_RES_EXCEEDED";
            break;

        case CCSP_ERR_UNKNOWN_DU:
            s = "CCSP_ERR_UNKNOWN_DU";
            break;

        case CCSP_ERR_INVALID_DU_STATE:
            s = "CCSP_ERR_INVALID_DU_STATE";
            break;

        case CCSP_ERR_DOWNGRADE_NOT_PERMITTED:
            s = "CCSP_ERR_DOWNGRADE_NOT_PERMITTED";
            break;

        case CCSP_ERR_VERSION_NOT_SPECIFIED:
            s = "CCSP_ERR_VERSION_NOT_SPECIFIED";
            break;

        case CCSP_ERR_VERSION_EXISTS:
            s = "CCSP_ERR_VERSION_EXISTS";
            break;

        case CCSP_CR_ERR_NAMESPACE_OVERLAP:
            s = "CCSP_CR_ERR_NAMESPACE_OVERLAP";
            break;

        case CCSP_CR_ERR_UNKNOWN_COMPONENT:
            s = "CCSP_CR_ERR_UNKNOWN_COMPONENT";
            break;

        case CCSP_CR_ERR_NAMESPACE_MISMATCH:
            s = "CCSP_CR_ERR_NAMESPACE_MISMATCH";
            break;

        case CCSP_CR_ERR_UNSUPPORTED_NAMESPACE:
            s = "CCSP_CR_ERR_UNSUPPORTED_NAMESPACE";
            break;

        case CCSP_CR_ERR_DP_COMPONENT_VERSION_MISMATCH:
            s = "CCSP_CR_ERR_DP_COMPONENT_VERSION_MISMATCH";
            break;

        case CCSP_CR_ERR_INVALID_PARAM:
            s = "CCSP_CR_ERR_INVALID_PARAM";
            break;

        case CCSP_CR_ERR_UNSUPPORTED_DATATYPE:
            s = "CCSP_CR_ERR_UNSUPPORTED_DATATYPE";
            break;

        case CCSP_CR_ERR_SESSION_IN_PROGRESS:
            s = "CCSP_CR_ERR_SESSION_IN_PROGRESS";
            break;

        case CCSP_INVALID_PSMCLI_CMD:
            s = "CCSP_INVALID_PSMCLI_CMD";
            break;

        default:
            s = "unknown CCSP error";
            break;

    }

    return s;
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
    int i;
    int pam_group_id = INVALID;
    rdk_component_t *rdkc;

    // Search for the 'pam' component
    for (i=0; i<num_rdk_components; i++)
    {
        rdkc = &rdk_components[i];
        if (strcmp(rdkc->group_name, "pam") == 0)
        {
            pam_group_id = i;
        }
    }

    // Exit if unable to find the 'pam' component
    if (pam_group_id == INVALID)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // Populate structure specifying the parameters to get
    pv.num_entries = 2;
    pv.vector = params;
    params[0].key = "Device.DeviceInfo.ManufacturerOUI";
    params[0].value = NULL;
    params[1].key = "Device.DeviceInfo.SerialNumber";
    params[1].value = NULL;

    // Exit if failed to retrieve the parameters
    USP_ASSERT(strcmp(rdk_components[pam_group_id].group_name, "pam")==0);
    err = RDK_GetGroup(pam_group_id, &pv);
    if (err != USP_ERR_OK)
    {
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
    int ccsp_err;
    char buf[MAX_DM_PATH];
    rdk_component_t *rdkc;

    // Exit if this function is called before D-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to D-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Append a '.' to the end of the object path
    USP_SNPRINTF(buf, sizeof(buf), "%s.", path);

    // Exit if the add failed
    rdkc = &rdk_components[group_id];
    ccsp_err = CcspBaseIf_AddTblRow(bus_handle, rdkc->component_name, rdkc->dbus_path, RDK_SESSION_ID, buf, instance);
    if (ccsp_err != CCSP_SUCCESS)
    {
        USP_ERR_SetMessage("%s: CcspBaseIf_AddTblRow(%s) failed (%d - %s)", __FUNCTION__, buf, ccsp_err, ToCcspErrString(ccsp_err));
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
    int ccsp_err;
    char buf[MAX_DM_PATH];
    rdk_component_t *rdkc;

    // Exit if this function is called before D-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to D-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Append a '.' to the end of the object path
    USP_SNPRINTF(buf, sizeof(buf), "%s.", path);

    // Exit if the delete failed
    rdkc = &rdk_components[group_id];
    ccsp_err = CcspBaseIf_DeleteTblRow(bus_handle, rdkc->component_name, rdkc->dbus_path, RDK_SESSION_ID, buf);
    if (ccsp_err != CCSP_SUCCESS)
    {
        USP_ERR_SetMessage("%s: CcspBaseIf_DeleteTblRow(%s) failed (%d - %s)", __FUNCTION__, buf, ccsp_err, ToCcspErrString(ccsp_err));
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
    int ccsp_err;
    char **paths = NULL;
    rdk_component_t *rdkc;
    int num_values = 0;
    parameterValStruct_t **values = NULL;
    parameterValStruct_t *val;
    int err = USP_ERR_OK;

    // Exit if this function is called before D-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to D-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Copy the paths of the parameters to get into the paths array
    paths = USP_MALLOC((params->num_entries)*sizeof(char*));
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
    rdkc = &rdk_components[group_id];
    ccsp_err = CcspBaseIf_getParameterValues(bus_handle, rdkc->component_name, rdkc->dbus_path, paths, params->num_entries, &num_values, &values);

#ifdef LOG_RDK_GET_TIME
    gettimeofday(&tv, NULL);
    double finish_time = (double)tv.tv_sec + (double)tv.tv_usec/(double)1000000.0;
    double delta_time = finish_time - start_time;
    USP_LOG_Info("%s: %lf %s %s", __FUNCTION__, delta_time, rdkc->group_name, params->vector[0].key);
#endif

    // Exit if unable to get the parameters
    if (ccsp_err != CCSP_SUCCESS)
    {
        USP_ERR_SetMessage("%s: CcspBaseIf_getParameterValues() failed (%d - %s)", __FUNCTION__, ccsp_err, ToCcspErrString(ccsp_err));
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Iterate over all returned values, copying them into the params vector
    for (i=0; i<num_values; i++)
    {
        val = values[i];
        USP_ARG_ReplaceWithHint(params, val->parameterName, val->parameterValue, i);
    }

    err = USP_ERR_OK;

exit:
    // Clean up
    free_parameterValStruct_t(bus_handle, num_values, values);
    USP_FREE(paths);

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
    int ccsp_err;
    rdk_component_t *rdkc;
    parameterValStruct_t *rdk_params;
    parameterValStruct_t *pvs;
    int err = USP_ERR_OK;
    char *fault_param = NULL;
    kv_pair_t *kv;
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;

    // Exit if this function is called before D-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to D-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form the rdk_params structure to pass to CcspBaseIf_setParameterValues()
    rdkc = &rdk_components[group_id];
    rdk_params = USP_MALLOC(params->num_entries * sizeof(parameterValStruct_t));
    for (i=0; i < params->num_entries; i++)
    {
        pvs = &rdk_params[i];
        kv = &params->vector[i];
        pvs->parameterName = kv->key;
        pvs->parameterValue = kv->value;
        pvs->type = UspTypeToRdkType(param_types[i]);
    }

    // Exit if unable to set the parameters, logging the first parameter that caused the fault
    #define RDK_COMMIT_NOW 1
    ccsp_err = CcspBaseIf_setParameterValues(bus_handle, rdkc->component_name, rdkc->dbus_path, 
                                           RDK_SESSION_ID, CCSP_USP_WRITE_ID,
                                           rdk_params, params->num_entries,
                                           RDK_COMMIT_NOW, &fault_param);
    if (ccsp_err != CCSP_SUCCESS)
    {
        // Exit if no parameter indicated by RDK
        err = USP_ERR_SET_FAILURE;
        if (fault_param == NULL)
        {
            USP_ERR_SetMessage("%s: CcspBaseIf_setParameterValues() failed (%d - %s)", __FUNCTION__, ccsp_err, ToCcspErrString(ccsp_err));
        }
        else
        {
            // If the code gets here, then a parameter was indicated by RDK
            USP_ERR_SetMessage("%s: CcspBaseIf_setParameterValues(%s) failed (%d - %s)", __FUNCTION__, fault_param, ccsp_err, ToCcspErrString(ccsp_err));
    
            // Determine the index of the failed parameter in the parameters we were attempting to set
            for (i=0; i < params->num_entries; i++)
            {
                kv = &params->vector[i];
                if (strcmp(kv->key, fault_param)==0)
                {
                    *failure_index = i;
                    break;
                }
            }

            // Free the RDK allocated fault parameter string, now that we have finished with it
            bus_info->freefunc(fault_param);
        }

        goto exit;
    }

exit:
    // Clean up
    USP_FREE(rdk_params);

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
    int i;
    int ccsp_err;
    int err;
    parameterInfoStruct_t **param_infos = NULL;
    parameterInfoStruct_t *param_info;
    int num_param_infos = 0;
    rdk_component_t *rdkc;
    char *name;
    int len;

    // Exit if this function is called before D-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to D-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to determine all instances provided by this rdk component
    rdkc = &rdk_components[group_id];

    ccsp_err = CcspBaseIf_getParameterNames(bus_handle, rdkc->component_name, rdkc->dbus_path, path, 0, 
                                          &num_param_infos, &param_infos);
    if (ccsp_err != CCSP_SUCCESS)
    {
        // NOTE: getParameterNames may fail if the table has 0 entries, so just log a warning for this
        USP_LOG_Warning("%s: CcspBaseIf_getParameterNames(%s) failed (%d- %s). Returning 0 instances for this object.", __FUNCTION__, path, ccsp_err, ToCcspErrString(ccsp_err));
        *expiry_period = 30;
        return USP_ERR_OK;
    }

    // Iterate over all parameters and objects found
    for (i=0; i<num_param_infos; i++)
    {
        param_info = param_infos[i];
        name = param_info->parameterName;
        len = strlen(name);

        // If this is an object instance, then refresh it in the data model
        if ((len >= 2) && (name[len-1] == '.') && (IS_NUMERIC(name[len-2])))
        {
            err = USP_DM_RefreshInstance(name);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }
        }
    }

    // If the code gets here, then all object instances were successfully added to the data model
    err = USP_ERR_OK;
    *expiry_period = 30;

exit:
    // Free the CcspBaseIf allocated structure, as we have finished with it
    free_parameterInfoStruct_t(bus_handle, num_param_infos, param_infos);
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
    return RdkResetInner("pam", "Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.RPC.RebootDevice", "Device, source=usp-reboot", "Reboot");
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
    return RdkResetInner("pam", "Device.X_CISCO_COM_DeviceControl.FactoryReset", "Router", "Factory Reset");
}

/*********************************************************************//**
**
** RdkResetInner
**
** Called to perform a factory reset or a reboot by writing to the specified parameter
** NOTE: This function exits the USP Agent executable after successfully initiating the required action
**
** \param   group_name - name of the group that the parameter belongs to
** \param   path - full data model path of the parameter to write to
** \param   value - value to write to the parameter
** \param   debug_msg - log message to print out before rebooting
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int RdkResetInner(char *group_name, char *path, char *value, char *debug_msg)
{
    int ccsp_err;
    int group_id;
    rdk_component_t *rdkc;
    parameterValStruct_t rdk_param;
    char *fault_param = NULL;

    USP_ASSERT(bus_handle == NULL); // Because CCSP_USP_PA_Stop() is called before performing a reboot/factory reset

    // Exit if unable to re-connect to the RDK message bus
    ccsp_err = CCSP_Message_Bus_Init((char*)USPPA_COMPONENT_NAME, (char*)CONF_FILENAME, &bus_handle, malloc, free);
    if (ccsp_err != 0)
    {
        USP_ERR_SetMessage("%s: CCSP_Message_Bus_Init() failed (%d - %s)", __FUNCTION__, ccsp_err, ToCcspErrString(ccsp_err));
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if this function is called before D-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to D-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to determine the group_id of the parameter controlling reboot
    group_id = CalcGroupId(group_name);
    if (group_id == INVALID)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // Fill in the details of the parameter controlling reboot or factory reset
    rdk_param.parameterName = path;
    rdk_param.parameterValue = value;
    rdk_param.type = ccsp_string;

    // Exit if unable to set the parameter
    rdkc = &rdk_components[group_id];
    ccsp_err = CcspBaseIf_setParameterValues(bus_handle, rdkc->component_name, rdkc->dbus_path, 
                                             RDK_SESSION_ID, CCSP_USP_WRITE_ID,
                                             &rdk_param, 1,
                                             RDK_COMMIT_NOW, &fault_param);
    if (ccsp_err != CCSP_SUCCESS)
    {
        USP_ERR_SetMessage("%s: CcspBaseIf_setParameterValues(%s) failed (%d - %s)", __FUNCTION__, path, ccsp_err, ToCcspErrString(ccsp_err));
        return USP_ERR_INTERNAL_ERROR;
    }

    // USP Agent exits
    USP_LOG_Info("%s: Performing %s", __FUNCTION__, debug_msg);
    exit(0);
}

/*********************************************************************//**
**
** DiscoverDM_Components
**
** Discovers the data model provider components available on this device
**
** \param   objs_filename - name of file to write the discovered data model provider components into
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DiscoverDM_Components(char *comps_filename)
{
    int i;
    int ccsp_err;
    componentStruct_t **components = NULL;
    int num_components = 0;
    componentStruct_t *comp;
    kv_vector_t found_comps;
    char *group_name;
    char buf[256];
    int err;

    USP_ARG_Init(&found_comps);

    // Exit if unable to discover all provider components
    #define SUBSYSTEM_PREFIX "eRT."
    ccsp_err = CcspBaseIf_discComponentSupportingNamespace(bus_handle,
                                                           SUBSYSTEM_PREFIX "com.cisco.spvtg.ccsp.CR",
                                                           "Device.",
                                                           SUBSYSTEM_PREFIX,
                                                           &components, &num_components);
    if (ccsp_err != CCSP_SUCCESS)
    {
        USP_ERR_SetMessage("%s: CcspBaseIf_discComponentSupportingNamespace() failed (%d - %s)", __FUNCTION__, ccsp_err, ToCcspErrString(ccsp_err));
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all components found, adding them to the kv vector
    for (i=0; i<num_components; i++)
    {
        // Extract a short group_name
        comp = components[i];
        group_name = strrchr(comp->componentName, '.');
        if (group_name != NULL)
        {
            USP_SNPRINTF(buf, sizeof(buf), "%s %s", comp->componentName, comp->dbusPath);
            group_name++;                       // Skip after the '.'
            USP_ARG_Add(&found_comps, group_name, buf);
        }
    }

    // Write the component file
    err = WriteDMConfig(comps_filename, "w", &found_comps, "# Configuration file for data model provider components accessible over USP\n");
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    err = USP_ERR_OK;

exit:
    free_componentStruct_t(bus_handle, num_components, components);
    USP_ARG_Destroy(&found_comps);

    return USP_ERR_OK;
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
    int i;
    int err;
    rdk_component_t *rdkc;
    kv_vector_t rdk_objects;
    kv_vector_t rdk_params;
    kv_vector_t rdk_missing_objs;

    // Exit if this function is called before D-Bus has been connected to
    if (bus_handle == NULL)
    {
        USP_ERR_SetMessage("%s: called before connected to D-Bus", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Initialise vectors to put the discovered data model configuration into
    USP_ARG_Init(&rdk_objects);
    USP_ARG_Init(&rdk_params);
    USP_ARG_Init(&rdk_missing_objs);

    // Iterate over all RDK components, discovering the parameters and objects that they provide
    for (i=0; i<num_rdk_components; i++)
    {
        rdkc = &rdk_components[i];
        (void)DiscoverDM_ForComponent(rdkc, &rdk_objects, &rdk_params);  // Intentionally ignoring any errors
    }

    // Determine all table objects which do not currently have any instances, but do have a 'NumberOfEntries' parameter
    AddMissingObjs(&rdk_objects, &rdk_params, &rdk_missing_objs);

    // Exit if unable to write either of the files successfully
    err = USP_ERR_OK;
    err |= WriteDMConfig(params_filename, "w", &rdk_params, "# Configuration file for data model parameters accessible over USP\n");
    err |= WriteDMConfig(objs_filename, "w", &rdk_objects, "# Configuration file for data model objects accessible over USP\n");
    err |= WriteDMConfig(objs_filename, "a", &rdk_missing_objs, "\n# Parameters for the following tables need to be added manually\n");
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

exit:
    USP_ARG_Destroy(&rdk_objects);
    USP_ARG_Destroy(&rdk_params);
    USP_ARG_Destroy(&rdk_missing_objs);

    return err;
}

/*********************************************************************//**
**
** DiscoverDM_ForComponent
**
** Discovers the data model provided by the specified component
**
** \param   rdkc - component providing part of the data model
** \param   rdk_objects - key value vector of data model object path vs properties
** \param   rdk_params - key value vector of data model parameter path vs properties
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DiscoverDM_ForComponent(rdk_component_t *rdkc, kv_vector_t *rdk_objects, kv_vector_t *rdk_params)
{
    int i;
    int ccsp_err;
    int err;
    parameterInfoStruct_t **param_infos = NULL;
    parameterInfoStruct_t *param_info;
    int num_param_infos = 0;
    char *write_status;

    // Exit if unable to determine all instances provided by this rdk component
    USP_LOG_Info("%s: Getting parameters and objects for '%s'", __FUNCTION__, rdkc->group_name);
    ccsp_err = CcspBaseIf_getParameterNames(bus_handle, rdkc->component_name, rdkc->dbus_path, "Device.", 0, 
                                          &num_param_infos, &param_infos);
    if (ccsp_err != CCSP_SUCCESS)
    {
        USP_LOG_Error("%s: CcspBaseIf_getParameterNames(%s) failed (%d- %s)", __FUNCTION__, rdkc->group_name, ccsp_err, ToCcspErrString(ccsp_err));
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all parameters and objects found
    for (i=0; i<num_param_infos; i++)
    {
        param_info = param_infos[i];
        write_status = (param_info->writable) ? "RW" : "RO";
        Add_NameToDM(rdkc, param_info->parameterName, write_status, rdk_objects, rdk_params);
    }

    // If the code gets here, then all object instances were successfully added to the data model
    err = USP_ERR_OK;

    // Free the CcspBaseIf allocated structure, as we have finished with it
    free_parameterInfoStruct_t(bus_handle, num_param_infos, param_infos);
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
** \param   rdk_objects - key value vector of data model object path vs properties
** \param   rdk_params - key value vector of data model parameter path vs properties
**
** \return  None
**
**************************************************************************/
void Add_NameToDM(rdk_component_t *rdkc, char *instantiated_path, char *write_status, kv_vector_t *rdk_objects, kv_vector_t *rdk_params)
{
    char schema_path[MAX_DM_PATH];
    int len;

    ConvertInstantiatedToSchemaPath(instantiated_path, schema_path, sizeof(schema_path));

    // Exit if length is too short to be considered a data model path
    len = strlen(schema_path);
    if (len < 4)
    {
        return;
    }

    if (schema_path[len-1] == '.')
    {
        // Only add multi-instance objects
        if (strcmp(&schema_path[len-4], "{i}.")==0)
        {
            schema_path[len-1] = '\0';      // Drop trailing dot
            Add_ObjectToDM(rdkc, schema_path, write_status, rdk_objects);
        }
    }
    else
    {
        // Must be a parameter
        Add_ParamToDM(rdkc, instantiated_path, schema_path, write_status, rdk_params);
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
void Add_ObjectToDM(rdk_component_t *rdkc, char *schema_path, char *write_status, kv_vector_t *rdk_objects)
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
    USP_SNPRINTF(buf, sizeof(buf), "%s %s", rdkc->group_name, write_status);
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
void Add_ParamToDM(rdk_component_t *rdkc, char *instantiated_path, char *schema_path, char *write_status, kv_vector_t *rdk_params)
{
    int ccsp_err;
    int num_values = 0;
    parameterValStruct_t **values = NULL;
    parameterValStruct_t *val;
    char *type_str;
    char *is_exist;
    char buf[128];

    // Exit if param already exists
    is_exist = USP_ARG_Get(rdk_params, schema_path, NULL);
    if (is_exist != NULL)
    {
        return;
    }

    // Exit if unable to get the parameter in order to determine its type (and also check that it is readable)
    ccsp_err = CcspBaseIf_getParameterValues(bus_handle, rdkc->component_name, rdkc->dbus_path, &instantiated_path, 1, &num_values, &values);
    if (ccsp_err != CCSP_SUCCESS)
    {
        USP_LOG_Error("%s: CcspBaseIf_getParameterValues() failed (%d - %s)", __FUNCTION__, ccsp_err, ToCcspErrString(ccsp_err));
        USP_LOG_Error("%s: WARNING: Not adding %s to the data model", __FUNCTION__, schema_path);
        return;
    }

    // Determine its type (as a string)
    val = values[0];
    type_str = RdkTypeToTypeString(val->type);

    // Add param
    USP_SNPRINTF(buf, sizeof(buf), "%s %s %s", rdkc->group_name, type_str, write_status);
    USP_ARG_Add(rdk_params, schema_path, buf);

    // Free data structure returned by CcspBaseIf_getParameterValues()
    free_parameterValStruct_t(bus_handle, num_values, values);
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
** AddMissingObjs
**
** Determines data model table objects which currently have no instances, but do have a 'NumberOfEntries' parameter
**
** \param   rdk_objects - key value vector of data model object path vs properties
** \param   rdk_params - key value vector of data model parameter path vs properties
** \param   missing_objs - key value vector to add the missing objects into
**
** \return  None
**
**************************************************************************/
void AddMissingObjs(kv_vector_t *rdk_objects, kv_vector_t *rdk_params, kv_vector_t *missing_objs)
{
    int i;
    kv_pair_t *kv;
    int len;
    int offset;
    char *p;
    char schema_path[MAX_DM_PATH];
    char buf[128];
    char *is_exist;

    // Iterate over all parameters, ensuring there are tables for all 'NumberOfEntries' parameters
    for (i=0; i < rdk_params->num_entries; i++)
    {
        #define ENTRIES_STRING "NumberOfEntries"
        #define ENTRIES_STRING_LEN  (sizeof(ENTRIES_STRING)-1)  // NOTE: Does not include null terminator
        #define INSTANCE_STRING ".{i}"
        #define INSTANCE_STRING_LEN (sizeof(INSTANCE_STRING))   // NOTE: Includes null terminator
        kv = &rdk_params->vector[i];
        len = strlen(kv->key);
        if ((len > ENTRIES_STRING_LEN) && (len + INSTANCE_STRING_LEN <= sizeof(schema_path)))
        {
            // Is this a parameter which ends in 'NumberOfEntries'
            offset = len - ENTRIES_STRING_LEN;
            if (strcmp(&kv->key[offset], ENTRIES_STRING)==0)
            {
                // Form the schema path for the object
                memcpy(schema_path, kv->key, offset);
                memcpy(&schema_path[offset], INSTANCE_STRING, INSTANCE_STRING_LEN);

                // Add this object if it hasn't already been added
                is_exist = USP_ARG_Get(rdk_objects, schema_path, NULL);
                if (is_exist == NULL)
                {
                    // Form object's properties
                    // NOTE: Guessing at read write status as RO
                    p = strchr(kv->value, ' '); 
                    *p = '\0';          // Temporarily truncate the value string, to form just the group_name
                    USP_SNPRINTF(buf, sizeof(buf), "%s RO", kv->value);
                    *p = ' ';           // Restore the group_name

                    // Add the object
                    USP_ARG_Add(missing_objs, schema_path, buf);
                }
            }
        }
    }
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
 
/*********************************************************************//**
**
** rdk_malloc
**
** Wrapper around malloc() called by CCSP API
**
** \param   size - number of bytes to allocate on the heap
**
** \return  pointer to allocated memory, or NULL if out of memory
**
**************************************************************************/
void *rdk_malloc(size_t size)
{
    void *ptr;
    ptr = malloc(size);
    return ptr;
}

/*********************************************************************//**
**
** rdk_free
**
** Wrapper around free() called by CCSP API
**
** \param   ptr - pointer to memory to deallocate from the heap
**
** \return  None
**
**************************************************************************/
void rdk_free(void *ptr)
{
    free(ptr);
}


