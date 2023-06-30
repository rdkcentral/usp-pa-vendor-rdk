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
#ifndef __LCM_DATAMODEL_C__
#define __LCM_DATAMODEL_C__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "usp_err_codes.h"
#include "vendor_defs.h"
#include "vendor_api.h"
#include "usp_api.h"

#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include <rbus.h>

#if __STDC_VERSION__ >= 201112L
#define STATIC_ASSERT(_cond,_str) _Static_assert(_cond,_str)
#else
//static assert not supported pre-c11
#define STATIC_ASSERT(_cond,_str)
#endif

#define NUM_ELEM(x) (sizeof((x)) / sizeof((x)[0]))
#define DEV_SM_ROOT "Device.SoftwareModules."

rbusHandle_t rbus_handle = NULL;

//forward decelerations
static int LCM_Async_rbus_translate(dm_req_t *req, kv_vector_t *in, int instance,char * extra_args [],rbusValueType_t arg_types [], int num_extra_args,void (*ptr)(rbusHandle_t ,const char* , rbusError_t , rbusObject_t));
static void LCM_Generic_callback(rbusHandle_t handle,const char* method, rbusError_t err, rbusObject_t params);


//macro used to create a new array in the current scope with the same path but with an appended dot to the string
#define PATH_APPEND_DOT(var_name, path) \
    char var_name [strlen(path) + 2]; \
    sprintf(var_name,"%s.",path);

static int GetRbusValue(const char * name,rbusValue_t * value)
{
    int err = -1;
    rbusError_t error_code;

    if (value != NULL && rbus_handle != NULL)
    {
        error_code = rbus_get(rbus_handle, name, value);
        if(error_code != RBUS_ERROR_SUCCESS)
        {
            fprintf(stderr,"failed to get value%s\nreturned error%i\n",name,(int)error_code);
        }
        else
        {
            err = USP_ERR_OK;
        }
    }

    return err;

}

//iterates over rbus data and passes it through to the USP event
static void LCM_Translate_Event(__attribute((unused)) rbusHandle_t handle, rbusEvent_t const* event,__attribute((unused)) rbusEventSubscription_t* subscription)
{
    rbusProperty_t prop = rbusObject_GetProperties(event->data);

    kv_vector_t * output = malloc(sizeof(kv_vector_t)); //adding to this vector does a realloc but it needs to be assigned at least this to start with
    USP_ARG_Init(output);

    while (prop != NULL) 
    {
        const char * prop_name = rbusProperty_GetName(prop);
        rbusValue_t val = rbusProperty_GetValue(prop);
        const rbusValueType_t type = rbusValue_GetType(val);
        char num_str [21] = {0}; //up to -LLONG_MAX (18446744073709551615) num of characters + null terminator
        char * ptr = NULL;

        switch(type)
        {
            case RBUS_STRING: 
            {
                ptr = (char*)rbusValue_GetString(val,NULL);
                break;
            }
            case RBUS_BYTE: 
            {
                sprintf(num_str,"%u",rbusValue_GetByte(val));
                ptr = num_str;
                break;
            }
            case RBUS_INT8: 
            {
                sprintf(num_str,"%i",rbusValue_GetInt8(val));
                ptr = num_str;
                break;
            }
            case RBUS_UINT8: 
            {
                sprintf(num_str,"%u",rbusValue_GetUInt8(val));
                ptr = num_str;
                break;
            }
            case RBUS_INT16: 
            {
                sprintf(num_str,"%u",rbusValue_GetInt16(val));
                ptr = num_str;
                break;
            }
            case RBUS_UINT16: 
            {
                sprintf(num_str,"%u",rbusValue_GetUInt16(val));
                ptr = num_str;
                break;
            }
            case RBUS_INT32: 
            {
                sprintf(num_str,"%i",rbusValue_GetInt32(val));
                ptr = num_str;
                break;
            }
            case RBUS_UINT32:
            {
                sprintf(num_str,"%u",rbusValue_GetUInt32(val));
                ptr = num_str;
                break;
            }
            case RBUS_INT64:  
            {
                sprintf(num_str,"%"PRIi64,rbusValue_GetInt64(val));
                ptr = num_str;
                break;
            }
            case RBUS_UINT64: 
            {
                sprintf(num_str,"%"PRIu64,rbusValue_GetUInt64(val));
                ptr = num_str;
                break;
            }
            case RBUS_SINGLE:  
            {
                sprintf(num_str,"%.8f",rbusValue_GetSingle(val));
                ptr = num_str;
                break;
            }
            case RBUS_DOUBLE:  
            {
                sprintf(num_str,"%.8f",rbusValue_GetDouble(val));
                ptr = num_str;
                break;
            }
            case RBUS_DATETIME:
            {
                const rbusDateTime_t * tmp = rbusValue_GetTime(val);
                if (tmp != NULL) 
                {
                    //format time to a string ( as USP event args in obuspa are all char *) according to iso 8601
                    //re-use the num_str buffer, max size of this string should also be 20(1970-01-01T00:00:00Z)+1(null), so its fine.
                    struct tm val_as_tm;
                    rbusValue_UnMarshallRBUStoTM(&val_as_tm, tmp)
                    strftime(num_str, sizeof(num_str), "%Y-%m-%dT%H:%M:%SZ", &val_as_tmp);
                    ptr = num_str;
                }
                break;
            }
            case RBUS_BOOLEAN:
            {
                sprintf(num_str,"%s",rbusValue_GetBoolean(val) ? "True" : "False");
                ptr = num_str;
                break;
            }
            case RBUS_BYTES:
            case RBUS_PROPERTY:
            case RBUS_OBJECT:
            case RBUS_NONE:
            default: {
                fprintf(stderr,"the event handler cannot handle the type:%i for event arg: %s\n",type,prop_name);
                break;
            }
        }

        if (ptr != NULL ) 
        {
            USP_ARG_Add(output, (char*)prop_name , ptr );
        }

        prop = rbusProperty_GetNext(prop);
    }

    //ownership of the kv_vector_t is transferred by this function, so do not use (or free) after this
    const int usp_err = USP_SIGNAL_DataModelEvent((char*)event->name,output);
    if ( usp_err != USP_ERR_OK) {
        fprintf(stderr,"USP signal failed error code=%i\n",usp_err);
    }  
}

//finds and (un)subscribes to all events at the current level to the translate event, which passes through any data published by the rbus event to the usp event
// expects that a '.' is at then end of the name string i.e. device.example.
static void LCM_SubOrUnsubToAllEvents(const char *name, bool subscribe)
{
    rbusElementInfo_t* elems = NULL;
    rbusElementInfo_get(rbus_handle, name, -1 , &elems);

    rbusElementInfo_t* elem = elems;
    while(elem != NULL)
    {
        if  ( elem->type == RBUS_ELEMENT_TYPE_EVENT)
        {
            rbusError_t const error_code = subscribe ? rbusEvent_Subscribe(rbus_handle,elem->name, LCM_Translate_Event,  NULL, 0) : rbusEvent_Unsubscribe(rbus_handle,elem->name);
            if (error_code != RBUS_ERROR_SUCCESS)
            {
                fprintf(stderr,"%s returned error=%s\n",subscribe ? "subscribe" : "unsubscribe",rbusError_ToString(error_code));
            }
        }
        elem = elem->next;
    }
}

static int Add_RbusTableRow(dm_req_t *req) 
{
    uint32_t inst; //not used but address is used and can't be null
    PATH_APPEND_DOT(path_append_dot,req->path);
    char * index = NULL;
    if (req->inst->order > 0) 
    {
        index = malloc(10);// 9 characters in max length int , plus null terminator
        sprintf(index,"%i",req->inst->instances[req->inst->order-1]);
    }
    rbusError_t error_code = rbusTable_addRow(rbus_handle,path_append_dot,index,&inst );
    if (error_code != RBUS_ERROR_SUCCESS) 
    {
        fprintf(stderr,"Add Row returned error=%s\n",rbusError_ToString(error_code));
        return USP_ERR_GENERAL_FAILURE;
    }
    LCM_SubOrUnsubToAllEvents(path_append_dot,true);
    
    free(index);
    return USP_ERR_OK;
}

//these do nothing (for now)
static int ValidateAdd_RbusTable(dm_req_t *req) { return USP_ERR_OK;  }
static int ValidateDelete_RbusTable(dm_req_t *req)  { return USP_ERR_OK;  }
static int NotifyAdd_RbusTable(dm_req_t *req) { return USP_ERR_OK;  }
static int NotifyDelete_RbusTable(dm_req_t *req)  { return USP_ERR_OK;  }

static int Delete_RbusTableRow(dm_req_t *req) 
{
    //req truncates the last '.' from the path which rbus expects to be there, so create a new var with it added back on
    PATH_APPEND_DOT(path_append_dot,req->path);
    LCM_SubOrUnsubToAllEvents(path_append_dot,false);
    rbusError_t error_code = rbusTable_removeRow(rbus_handle, path_append_dot );
    if (error_code != RBUS_ERROR_SUCCESS)
    {
        fprintf(stderr,"Remove Row returned error=%s\n",rbusError_ToString(error_code));
        return USP_ERR_GENERAL_FAILURE;
    }
    
    return USP_ERR_OK;
}

//if a table change happens in rbus USP needs to know about it
static void LCM_Handle_Table_Changes(__attribute((unused)) rbusHandle_t handle, rbusEvent_t const* event,__attribute((unused)) rbusEventSubscription_t* subscription)
{
    rbusProperty_t prop = rbusObject_GetProperties(event->data);
    const char * rowName = NULL;
    while (prop != NULL) 
    {
        const char * prop_name = rbusProperty_GetName(prop);
        rbusValue_t val = rbusProperty_GetValue(prop);
        if (strcmp("rowName",prop_name) == 0)
        {
            rowName = rbusValue_GetString(val,NULL);
            break;
        }
    }

    if (rowName == NULL) { return; }    //exit early if this is null as the required string was not found

    if (event->type == RBUS_EVENT_OBJECT_CREATED)
    {
        LCM_SubOrUnsubToAllEvents(rowName,true);
        //TODO can i check the data model for the presence of these before adding them? doing this if they do causes an error/warning at present and it would be nice to avoid that
        USP_SIGNAL_ObjectAdded((char*)rowName);
    }
    else if (event->type == RBUS_EVENT_OBJECT_DELETED)
    {
        LCM_SubOrUnsubToAllEvents(rowName,false);
        USP_SIGNAL_ObjectDeleted((char*)rowName);
    }
}

//synchronise the records of rows between rbus and ubus
static void LCM_setupRbusTable(const char * name)
{
    int numOfOutVals = 0;
    rbusProperty_t outputVals = NULL;
    const char *pInputParam[2] = {name, 0};

    rbusEvent_Subscribe( rbus_handle,name, LCM_Handle_Table_Changes,  NULL, 0); 

    rbusError_t error_code = rbus_getExt(rbus_handle, 1, pInputParam, &numOfOutVals, &outputVals);
    if (error_code != RBUS_ERROR_SUCCESS)
    {
        fprintf(stderr,"could not get component \"%s\"\nreturned error %s\n",pInputParam[0],rbusError_ToString(error_code));
    }

    int valid_index_count = 0;
    int valid_indexes [numOfOutVals]; //there could be up to this many rows in the table

    int valid_sub_tables = 0;
    char * sub_tables [numOfOutVals]; //there could be up to this many sub-tables in the table

    memset(valid_indexes,0,sizeof(int)* numOfOutVals);
    memset(sub_tables,0,sizeof(char*)* numOfOutVals);

    int const name_length = strlen(name);
    //for both buffers 9 characters added to length because of max int characters , plus null terminator;
    char row_name_buffer[name_length + 10];
    char index [10] = {0};
    int table_index_offset;
    int sub_table_offset;
    rbusProperty_t next = outputVals;
    for (int i = 0 ; i < numOfOutVals; i++) 
    {
        const char * property_name = rbusProperty_GetName(next);
        next = rbusProperty_GetNext(next);
        //get the index from the name of the property by reading past the input name up to the next '.'
        table_index_offset = name_length;
        for (; property_name[table_index_offset] != 0 && property_name[table_index_offset] != '.' ;table_index_offset++) {}//find the next '.' or end of string by null termination

        //figure out if this property is a sub-table
        if (property_name[table_index_offset] != 0) { 
            sub_table_offset = table_index_offset +1; //move past the last read '.'

            // can read up to the next 2 '.'s i.e.   ".sub_table.X."
            for (; property_name[sub_table_offset] != 0 && property_name[sub_table_offset] != '.' ;sub_table_offset++) {}
            for (; property_name[sub_table_offset] != 0 && property_name[sub_table_offset] != '.' ;sub_table_offset++) {}

            if (property_name[sub_table_offset] !=0) { 
                //check that the sub-table is unique
                bool contains_match=false;
                for (int j = 0 ; j < valid_sub_tables && !contains_match; j++) {
                    if (memcmp(property_name,sub_tables[j],sub_table_offset) == 0) {
                        contains_match = true;
                    }
                }
                // if not already in array, put it in
                if (!contains_match) {
                    sub_tables[valid_sub_tables] = malloc(strlen(property_name));
                    memcpy(sub_tables[valid_sub_tables],property_name,sub_table_offset+1);
                    sub_tables[valid_sub_tables][sub_table_offset+1] = 0; //null terminate
                    valid_sub_tables++;
                }
            }
        }

        //copy the index string to the buffer then combine them and register that row to the usp table
        int const index_length = table_index_offset-name_length;
        if ( (index_length) < sizeof(index))
        {
            memcpy(index,&property_name[name_length],index_length);
            index[index_length] = 0; //null terminate
        }
        int int_index = strtol(index,NULL,10);

        //check that the list of numbers doesn't already contain this row.
        if (int_index != valid_indexes[valid_index_count])
        {
            bool already_contains = false;
            for (int i = 0 ; i < numOfOutVals ; i ++)
            {
                if (int_index == valid_indexes[i])
                {
                    already_contains = true;
                    break;
                }
            }

            if (!already_contains)
            {
                valid_indexes[valid_index_count] = int_index;
                valid_index_count++;
            }
        }
    }

    for (int i = 0 ; i < valid_index_count; i++)
    {
        sprintf(row_name_buffer,"%s%i",name,valid_indexes[i]);
        LCM_SubOrUnsubToAllEvents(row_name_buffer,true);
        USP_SIGNAL_ObjectAdded(row_name_buffer); //inform USP that this object (i.e. the table row) exists and can be called
    }

    //recursively call for any sub-tables
    for (int i = 0 ; i < valid_sub_tables; i++)
    {
        LCM_setupRbusTable(sub_tables[i]);
        free(sub_tables[i]);
    }


    //fprintf(stderr,"table %s has %i existing rows\n",name,valid_index_count); //DEBUG

    rbusProperty_Release(outputVals);
}

static char *LCM_DeploymentUnit_InstallDU_inputArgs[] =
{
    "URL",
    "UUID",
    "Username",
    "Password",
    "ExecutionEnvRef",
};

static int LCM_DeploymentUnit_InstallDU(dm_req_t *req, kv_vector_t *in, int instance)
{
    const int arg_num = NUM_ELEM(LCM_DeploymentUnit_InstallDU_inputArgs);
    rbusValueType_t arg_types [] = 
    {
        RBUS_STRING /* URL */,
        RBUS_STRING /* UUID */,
        RBUS_STRING /* Username */,
        RBUS_STRING /* Password */,
        RBUS_STRING /* ExecutionEnvRef */,
    };
    STATIC_ASSERT (arg_num == NUM_ELEM(arg_types), "these arrays must be the same size");
    return LCM_Async_rbus_translate(req,in,instance,LCM_DeploymentUnit_InstallDU_inputArgs,arg_types,arg_num,LCM_Generic_callback);
}

static int LCM_DeploymentUnit_Uninstall(dm_req_t *req, kv_vector_t *in, int instance)
{
    //no input arguments to uninstall
    return LCM_Async_rbus_translate(req,in,instance,NULL,NULL,0,LCM_Generic_callback);
}

//translates usp function arguments to rbus arguments. needs to know what type rbus is expecting ahead of time
static void USP_To_rbus_Function_Args(rbusValueType_t type,rbusValue_t value, char * USP_arg)
{
    int64_t int_val = 0;
    uint64_t uint_val = 0;
    double double_val = 0.00F;

    //handle all rbus types for inputs
    switch (type)
    {
        case RBUS_STRING : 
        {
            rbusValue_SetString(value, USP_arg);
            break;
        }
        case RBUS_BYTE: 
        {
            uint_val = strtol(USP_arg,NULL,10);
            rbusValue_SetByte(value,uint_val);
            break;
        }
        case RBUS_INT8: 
        {
            int_val = strtol(USP_arg,NULL,10);
            rbusValue_SetInt8(value,int_val);
            break;
        }
        case RBUS_UINT8: 
        {
            uint_val = strtoul(USP_arg,NULL,10);
            rbusValue_SetUInt8(value,uint_val);
            break;
        }
        case RBUS_INT16: 
        {
            int_val = strtol(USP_arg,NULL,10);
            rbusValue_SetInt16(value,int_val);
            break;
        }
        case RBUS_UINT16: 
        {
            uint_val = strtol(USP_arg,NULL,10);
            rbusValue_SetUInt16(value,uint_val);
            break;
        }
        case RBUS_INT32: 
        {
            int_val = strtol(USP_arg,NULL,10);
            rbusValue_SetInt32(value,int_val);
            break;
        }
        case RBUS_UINT32: 
        {
            uint_val = strtoul(USP_arg,NULL,10);
            rbusValue_SetUInt32(value,uint_val);
            break;
        }
        case RBUS_INT64:  
        {
            int_val = strtol(USP_arg,NULL,10);
            rbusValue_SetInt64(value,int_val);
            break;
        }
        case RBUS_UINT64:  
        {
            uint_val = strtol(USP_arg,NULL,10);
            rbusValue_SetUInt64(value,uint_val);
            break;
        }
        case RBUS_SINGLE:  
        {
            double_val = strtod(USP_arg,NULL);
            rbusValue_SetSingle(value,double_val);
            break;
        }
        case RBUS_DOUBLE:  
        {
            double_val = strtod(USP_arg,NULL);
            rbusValue_SetDouble(value,double_val);
            break;
        }
        case RBUS_DATETIME: 
        {
            //TODO this needs implementing, unsure if any functions even take this in, and parsing times can be tricky so 
            //don't implement until needed
            //rbusValue_SetTime(value,&data.rbus_time);
            break;
        }
        case RBUS_BOOLEAN:  
        {
            if (strcasecmp(USP_arg,"True") == 0)
            {
                rbusValue_SetBoolean(value,true);
            }
            else if (strcasecmp(USP_arg,"False") == 0)
            {
                rbusValue_SetBoolean(value,false);
            }
            break;
        }
        case RBUS_BYTES:
        case RBUS_PROPERTY:
        case RBUS_OBJECT:
        case RBUS_NONE:
        default: {
            fprintf(stderr,"not supported type value:%i\n",type);
            break;
        }
    }
}

//general handler for async rbus/USP functions, takes in expected arguments , parses them and runs the invoke async calls
static int LCM_Async_rbus_translate(dm_req_t *req, kv_vector_t *in, int instance,char * extra_args [],rbusValueType_t arg_types [], int num_extra_args,void (*ptr)(rbusHandle_t ,const char* , rbusError_t , rbusObject_t))
{
    rbusError_t ec;
    rbusObject_t in_params;
    rbusValue_t value;
    rbusProperty_t prop = NULL;

    char * rbus_string = NULL;

    rbusValue_Init(&value);
    rbusObject_Init(&in_params,NULL);

    rbusValue_SetInt32(value,instance);
    rbusObject_SetValue(in_params,"uspasynchandle",value);
    rbusValue_Release(value);
    
    for (int i = 0 ; i < num_extra_args; i ++)
    {
        rbus_string = USP_ARG_Get(in,extra_args[i],NULL);
        if (rbus_string != NULL)
        {
            rbusValue_Init(&value);
            USP_To_rbus_Function_Args(arg_types[i],value,rbus_string);
            
            rbusProperty_Init(&prop, extra_args[i], value);
            rbusObject_SetProperty(in_params, prop);

            rbusValue_Release(value);
            rbusProperty_Release(prop);   
        }
    }

    ec = rbusMethod_InvokeAsync(rbus_handle,req->path,in_params,ptr,0);
    if(ec!=RBUS_ERROR_SUCCESS) { return USP_ERR_COMMAND_FAILURE; }
    
    rbusObject_Release(in_params);

    return USP_ERR_OK;


}

char * LCM_DeploymentUnit_Update_inputArgs[] =
{
    "URL",
    "Username",
    "Password"
};

//Note that the callback may need to be specialized in for some functions, but doesn't for any of the currently implemented ones
static void LCM_Generic_callback(rbusHandle_t handle,const char* method, rbusError_t err, rbusObject_t params)
{
    rbusValue_t usp_rbus_value = rbusObject_GetValue(params,"uspasynchandle");
    if (usp_rbus_value != NULL)
    {
        const int instance = rbusValue_GetInt32(usp_rbus_value);
        const int ec = (err==RBUS_ERROR_SUCCESS) ? USP_ERR_OK : USP_ERR_COMMAND_FAILURE;

        USP_SIGNAL_OperationComplete(instance,ec,NULL,NULL);
    } 
    else 
    {
        fprintf(stderr,"no uspasynchandle in callback cannot call USP_SIGNAL_OperationComplete\n");
    }
}

static int LCM_DeploymentUnit_Update(dm_req_t *req, kv_vector_t *in, int instance)
{
    const int arg_num = NUM_ELEM(LCM_DeploymentUnit_Update_inputArgs);
    rbusValueType_t arg_types [] = 
    {
        RBUS_STRING /* URL */,
        RBUS_STRING /* Username */,
        RBUS_STRING /* Password */
    };
    STATIC_ASSERT (arg_num == NUM_ELEM(arg_types), "these arrays must be the same size");
    return LCM_Async_rbus_translate(req,in,instance,LCM_DeploymentUnit_Update_inputArgs,arg_types,arg_num,LCM_Generic_callback);
}

static int GetStringRbus(dm_req_t *req, char *buf, int len) 
{
    rbusValue_t value = NULL;
    int err = -1;
    int rbus_len = 0;
    const char * str = NULL;

    rbusValue_Init(&value);
    err = GetRbusValue(req->path,&value);
    str = rbusValue_GetString(value, &rbus_len);
    if (str !=NULL)
    {
        //if the string returned from rbus is bigger than usp can support then truncate the value it returns
        if (strlen(str) >= MAX_DM_VALUE_LEN)
        {
            fprintf(stderr,"had to truncate %zi byte(s) because of buffer limits in rbus",strlen(str)-MAX_DM_VALUE_LEN);
            rbus_len = MAX_DM_VALUE_LEN -1;
        }
        strncpy(buf,str,rbus_len+1); //+1 to include null terminator
        err = USP_ERR_OK;
    }

    rbusValue_Release(value);
    return err;
}

static int GetInt32Rbus(dm_req_t *req, char *buf, int len) 
{
    rbusValue_t value = NULL;
    int err = -1;
    int32_t int_val = 0;

    rbusValue_Init(&value);
    err = GetRbusValue(req->path,&value);
    int_val = rbusValue_GetInt32(value);
    sprintf(buf,"%i",int_val);
    rbusValue_Release(value);
    return err;
}

static int GetBoolRbus(dm_req_t *req, char *buf, int len) 
{
    rbusValue_t value = NULL;
    int err = -1;
    bool b = 0;

    rbusValue_Init(&value);
    err = GetRbusValue(req->path,&value);
    b = rbusValue_GetBoolean(value);
    sprintf(buf,"%s", b ? "True" : "False");
    rbusValue_Release(value);
    return err;
}

static int SetRbusValue(const char * name,rbusValue_t * value)
{
    int err = -1;
    rbusError_t error_code;
    rbusSetOptions_t opts;

    if (value != NULL && rbus_handle != NULL)
    {
        opts.commit= true;
        error_code = rbus_set(rbus_handle, name, (*value), &opts);
        if(error_code != RBUS_ERROR_SUCCESS)
        {
            fprintf(stderr,"failed to set value%s\nreturned error%i\n",name,(int)error_code);
        }
        else
        {
            err = USP_ERR_OK;
        }
    }
    
    return err;
}

static int SetBoolRbus (dm_req_t *req, char *in)
{
    rbusValue_t value = NULL;
    int err = -1;

    rbusValue_Init(&value);
    if (strcasecmp(in,"True") == 0)
    {
        rbusValue_SetBoolean(value,true);
        err = SetRbusValue(req->path,&value);
    }
    else if (strcasecmp(in,"False") == 0)
    {
        rbusValue_SetBoolean(value,false);
        err = SetRbusValue(req->path,&value);
    }

    rbusValue_Release(value);
    return err;
}

static int SetInt32Rbus(dm_req_t *req, char *in)
{
    rbusValue_t value = NULL;
    int err = -1;

    rbusValue_Init(&value);
    int const int_val = strtol(in,NULL,10);
    if (errno == 0)
    {
        rbusValue_SetInt32(value,int_val);
        err = SetRbusValue(req->path,&value);
    }

    rbusValue_Release(value);
    return err;
}

static int SetStringRbus(dm_req_t *req, char *in)
{
    rbusValue_t value = NULL;
    int err = -1;

    rbusValue_Init(&value);
    //if the string is too long, it will overflow buffers so truncate at max length
    if (strlen(in) >= MAX_DM_VALUE_LEN) 
    {
        fprintf(stderr,"had to truncate %zi byte(s) because of buffer limits in rbus",strlen(in)-MAX_DM_VALUE_LEN);
        in[MAX_DM_VALUE_LEN-1]= 0; //set the last possible character inside the buffer to a null terminator
        
    }
    rbusValue_SetString(value,in);
    err = SetRbusValue(req->path,&value);

    rbusValue_Release(value);
    return err;
}

//general handler for synchronous rbus/USP functions, takes in expected arguments , parses them and runs the invoke calls
static int LCM_Generic_Method(char * Args[] , rbusValueType_t arg_types [] , int num_args,  dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
    int err = USP_ERR_OK;

    rbusError_t rc = RBUS_ERROR_SUCCESS;
    rbusObject_t  in_params = NULL, out_params = NULL , next = NULL;
    rbusValue_t temp_value = NULL;
    rbusProperty_t temp_prop = NULL;
    char * rbus_string = NULL;
    const char * rbus_name = NULL;

    rbusObject_Init(&in_params, NULL);
    USP_ARG_Init(output_args);

    //build up the arguments for rbus
    for (int i = 0 ; i < num_args ; i++)
    {
        rbus_string = USP_ARG_Get(input_args,Args[i],NULL);
        if (rbus_string != NULL)
        {
            rbusValue_Init(&temp_value);
            
            USP_To_rbus_Function_Args(arg_types[i],temp_value,rbus_string);

            rbusProperty_Init(&temp_prop, Args[i], temp_value);
            rbusObject_SetProperty(in_params, temp_prop);

            rbusValue_Release(temp_value);
            rbusProperty_Release(temp_prop);
        }
    }

    rc = rbusMethod_Invoke(rbus_handle,req->path,in_params,&out_params);
    rbusObject_Release(in_params);

    if (rc == RBUS_ERROR_SUCCESS)
    {
        next = out_params;
        while (next != NULL)
        {
            temp_prop = rbusObject_GetProperties(out_params);
            if (temp_prop == NULL ) { break; } 
            temp_value = rbusProperty_GetValue(temp_prop);
            if (temp_value == NULL ) { break; }
            rbus_string = rbusValue_ToString(temp_value, NULL, 0);
            rbus_name = rbusProperty_GetName(temp_prop);

            if (rbus_name != NULL)
            {
                USP_ARG_Add(output_args, (char*)rbus_name, rbus_string);
            }
            free(rbus_string);
            next = rbusObject_GetNext(out_params);
        }
    }
    else
    {
        //translate rbus error code to usp equivalent
        switch(rc)
        {
            //TODO check these are correct
            case RBUS_ERROR_INVALID_OPERATION:
                err = USP_ERR_COMMAND_FAILURE;
                break;
            case RBUS_ERROR_INVALID_INPUT:
                err = USP_ERR_INVALID_ARGUMENTS;
                break;
            default:
                err = USP_ERR_GENERAL_FAILURE;
                break;
        }
    }

        rbusObject_Release(out_params);
        return err;
}

static char *LCM_ExecutionUnit_SetRequestedState_inputArgs[] =
{
    "RequestedState" // RequestedState=Idle, RequestedState=Active
};

static int LCM_ExecutionUnit_SetRequestedState(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
    const int arg_num = NUM_ELEM(LCM_ExecutionUnit_SetRequestedState_inputArgs);
    rbusValueType_t arg_types [] = 
    {
        RBUS_STRING /* RequestedState */
    };
    STATIC_ASSERT (arg_num == NUM_ELEM(arg_types), "these arrays must be the same size");
    return LCM_Generic_Method (LCM_ExecutionUnit_SetRequestedState_inputArgs,arg_types,arg_num, req, command_key, input_args, output_args);
}

static char * LCM_ExecEnv_SetRunLevel_inputArgs[] =
{
    "RequestedRunLevel" // RequestedRunLevel=(-1:66535)
};

static int LCM_ExecEnv_SetRunLevel(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
    const int arg_num = NUM_ELEM(LCM_ExecEnv_SetRunLevel_inputArgs);
    rbusValueType_t arg_types [] = 
    {
        RBUS_INT32 /* RequestedRunLevel */
    };
    STATIC_ASSERT (arg_num == NUM_ELEM(arg_types), "these arrays must be the same size");
    return LCM_Generic_Method (LCM_ExecEnv_SetRunLevel_inputArgs,arg_types, arg_num,req, command_key, input_args, output_args);
}

static int LCM_ExecEnv_Reset(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
   return LCM_Generic_Method (NULL,NULL, 0,req, command_key, input_args, output_args);
}

static void LCM_RegisterDataModel(void)
{
    //TR-181 datamodel Registration for RBUS

    USP_REGISTER_AsyncOperation    (DEV_SM_ROOT "InstallDU()",LCM_DeploymentUnit_InstallDU,NULL);
    USP_REGISTER_OperationArguments(DEV_SM_ROOT "InstallDU()",
        LCM_DeploymentUnit_InstallDU_inputArgs,NUM_ELEM(LCM_DeploymentUnit_InstallDU_inputArgs),NULL,0);

    //
    //ExecutionUnit table
    //
    USP_REGISTER_Object(DEV_SM_ROOT "ExecutionUnit.{i}", 
    ValidateAdd_RbusTable, Add_RbusTableRow, NotifyAdd_RbusTable,
    ValidateDelete_RbusTable, Delete_RbusTableRow, NotifyDelete_RbusTable);

    USP_REGISTER_Param_NumEntries( 
    DEV_SM_ROOT "ExecutionUnitNumberOfEntries",
    DEV_SM_ROOT "ExecutionUnit.{i}");

    USP_REGISTER_VendorParam_ReadWrite(DEV_SM_ROOT "ExecutionUnit.{i}.Name"             ,GetStringRbus, SetStringRbus,NULL,DM_STRING);
    USP_REGISTER_VendorParam_ReadWrite(DEV_SM_ROOT "ExecutionUnit.{i}.Status"             ,GetStringRbus, SetStringRbus,NULL,DM_STRING);
    // SetRequestedState (RequestedState=Idle|Active)
    USP_REGISTER_SyncOperation(DEV_SM_ROOT "ExecutionUnit.{i}.SetRequestedState()", LCM_ExecutionUnit_SetRequestedState);
    USP_REGISTER_OperationArguments(DEV_SM_ROOT "ExecutionUnit.{i}.SetRequestedState()",
        LCM_ExecutionUnit_SetRequestedState_inputArgs,NUM_ELEM(LCM_ExecutionUnit_SetRequestedState_inputArgs),NULL,0);

    //
    //DeploymentUnit table
    //
    USP_REGISTER_Object(DEV_SM_ROOT "DeploymentUnit.{i}", 
    ValidateAdd_RbusTable, Add_RbusTableRow, NotifyAdd_RbusTable,
    ValidateDelete_RbusTable, Delete_RbusTableRow, NotifyDelete_RbusTable);

    USP_REGISTER_Param_NumEntries(
    DEV_SM_ROOT "DeploymentUnitNumberOfEntries",
    DEV_SM_ROOT "DeploymentUnit.{i}");

    USP_REGISTER_VendorParam_ReadWrite(DEV_SM_ROOT "DeploymentUnit.{i}.URL"     ,GetStringRbus, SetStringRbus,NULL,DM_STRING);
    USP_REGISTER_VendorParam_ReadWrite(DEV_SM_ROOT "DeploymentUnit.{i}.Status"  ,GetStringRbus, SetStringRbus,NULL,DM_STRING);


    //must be registered after the table
    USP_REGISTER_AsyncOperation    (DEV_SM_ROOT "DeploymentUnit.{i}.Uninstall()",LCM_DeploymentUnit_Uninstall,NULL);
    USP_REGISTER_OperationArguments(DEV_SM_ROOT "DeploymentUnit.{i}.Uninstall()",NULL,0,NULL,0);

    USP_REGISTER_AsyncOperation    (DEV_SM_ROOT "DeploymentUnit.{i}.Update()",LCM_DeploymentUnit_Update,NULL);
    USP_REGISTER_OperationArguments(DEV_SM_ROOT "DeploymentUnit.{i}.Update()",LCM_DeploymentUnit_Update_inputArgs,NUM_ELEM(LCM_DeploymentUnit_Update_inputArgs),NULL,0);

    //
    //ExecEnv table
    //
        USP_REGISTER_Object(DEV_SM_ROOT "ExecEnv.{i}", 
    ValidateAdd_RbusTable, Add_RbusTableRow, NotifyAdd_RbusTable,
    ValidateDelete_RbusTable, Delete_RbusTableRow, NotifyDelete_RbusTable);

    USP_REGISTER_Param_NumEntries(
    DEV_SM_ROOT "ExecEnvNumberOfEntries",
    DEV_SM_ROOT "ExecEnv.{i}");

    USP_REGISTER_VendorParam_ReadWrite(DEV_SM_ROOT "ExecEnv.{i}.Enable"          ,GetBoolRbus, SetBoolRbus,NULL,DM_BOOL);
    USP_REGISTER_VendorParam_ReadOnly (DEV_SM_ROOT "ExecEnv.{i}.Status"          ,GetStringRbus,DM_STRING);
    USP_REGISTER_VendorParam_ReadOnly (DEV_SM_ROOT "ExecEnv.{i}.Name"            ,GetStringRbus,DM_STRING);
    USP_REGISTER_VendorParam_ReadWrite(DEV_SM_ROOT "ExecEnv.{i}.InitialRunLevel" ,GetInt32Rbus, SetInt32Rbus,NULL,DM_INT);
    USP_REGISTER_VendorParam_ReadOnly (DEV_SM_ROOT "ExecEnv.{i}.CurrentRunLevel" ,GetInt32Rbus,DM_INT);

    USP_REGISTER_SyncOperation    (DEV_SM_ROOT "ExecEnv.{i}.SetRunLevel()",LCM_ExecEnv_SetRunLevel);
    USP_REGISTER_OperationArguments(DEV_SM_ROOT "ExecEnv.{i}.SetRunLevel()",LCM_ExecEnv_SetRunLevel_inputArgs,NUM_ELEM(LCM_ExecEnv_SetRunLevel_inputArgs),NULL,0);

    USP_REGISTER_SyncOperation    (DEV_SM_ROOT "ExecEnv.{i}.Reset()",LCM_ExecEnv_Reset);
    USP_REGISTER_OperationArguments(DEV_SM_ROOT "ExecEnv.{i}.Reset()",NULL,0,NULL,0);

    //commented out fields exist in the spec but are not implemented in the mock
    static char *DUStateChange_Args[] =
    {
        //"UUID",   //rfc4122
        "DeploymentUnitRef",
        //"Version",
        "CurrentState",
        "Resolved",
        //"ExecutionUnitRefList",
        "StartTime",  // iso 8601 formatted time
        "CompleteTime", // iso 8601 formatted time
        "OperationPerformed",
        "FaultCode",
        "FaultString"
    };
    USP_REGISTER_Event(DEV_SM_ROOT "DUStateChange!");
    USP_REGISTER_EventArguments(DEV_SM_ROOT "DUStateChange!", DUStateChange_Args, NUM_ELEM(DUStateChange_Args));

    return;
}

static bool CheckRbusProviderRunning(const char * path) {
    bool is_running = false;
    int numOfOutVals = 0;
    rbusProperty_t outputVals = NULL;
    const char *pInputParam[2] = {path, 0};

    if (rbus_getExt(rbus_handle, 1, pInputParam, &numOfOutVals, &outputVals) == RBUS_ERROR_SUCCESS) 
    {
        is_running = true;
    }
    rbusProperty_Release(outputVals);

    return is_running;
}

static pthread_t init_thread;
static bool stopped = false;
void * DatamodelInitThread(__attribute((unused)) void * ptr)
{
    //wait for an rbus provider providing the tables in the data model to be up and running
    const char * table_check [3]= 
    {
        DEV_SM_ROOT "ExecutionUnit.",
        DEV_SM_ROOT "DeploymentUnit.",
        DEV_SM_ROOT "ExecEnv."
    } ;

    for (int i = 0 ; i < 3; i ++)
    {
        while (!CheckRbusProviderRunning(table_check[i])) 
        {
            sleep(1);
            if (stopped) //allow this to exit in the case where the provider is never started before the program is stopped
            {
                return NULL;
            }
        }
    }
    

    //get the number of tables from rbus and synchronise them here
    LCM_setupRbusTable(DEV_SM_ROOT "ExecutionUnit.");
    LCM_setupRbusTable(DEV_SM_ROOT "DeploymentUnit.");
    LCM_setupRbusTable(DEV_SM_ROOT "ExecEnv.");

    //register all events in the top level provider (i.e. Events not in any tables)
    LCM_SubOrUnsubToAllEvents(DEV_SM_ROOT,true);

    return NULL;
}

static int LCM_VENDOR_Init(void)
{
    rbusError_t ec;
    ec = rbus_open(&rbus_handle, "usp_consumer");
    if (ec != RBUS_ERROR_SUCCESS) 
    {
        fprintf(stderr,"could not open bus\nreturned error %s\n",rbusError_ToString(ec));
        abort(); //possibly an over-reaction, might leave sockets or ipc or etc in weird states
    }
    
    LCM_RegisterDataModel();

    //spawn a thread to handle the rbus init. this allows the connection to be done without blocking any other vendor code
    pthread_create(&init_thread,NULL,&DatamodelInitThread,NULL);

    

    return USP_ERR_OK;
}

static int LCM_VENDOR_Start(void)
{
    return USP_ERR_OK;
}

static int LCM_VENDOR_Stop(void)
{
    //stop the init thread if its still running
    stopped = true;
    pthread_join(init_thread,NULL);
    //close the rbus connection
    if (rbus_handle != NULL)
    {
        rbus_close(rbus_handle);
    }

    return USP_ERR_OK;
}


#endif

