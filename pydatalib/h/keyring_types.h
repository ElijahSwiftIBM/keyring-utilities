/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
* Copyright Contributors to the Zowe Project.                                     *
*/


#ifndef _keyring_types
#define _keyring_types

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <gskcms.h>


#define MAX_FUNCTION_LEN 16          // may be adjusted
#define MAX_USERID_LEN 8
#define MAX_KEYRING_LEN 236
#define MAX_LABEL_LEN 32
#define MAX_CERTIFICATE_LEN 64*1024 // may be adjusted
#define MAX_PRIVATE_KEY_LEN 8*1024  // may be adjusted
#define MAX_SUBJECT_DN_LEN 2*1024   // may be adjusted
#define MAX_RECORD_ID_LEN 246
#define MAX_EXTRA_ARG_LEN 256       // may be adjusted

#define GETCERT_CODE 0x01
#define GETNEXT_CODE 0x02
#define DATA_ABORT_CODE 0x03
#define NEWRING_CODE 0x07
#define DATAPUT_CODE  0x08
#define DATAREMOVE_CODE 0x09
#define DELRING_CODE 0x0A
#define REFRESH_CODE 0x0B
#define HELP_CODE  0x00
#define NOTSUPPORTED_CODE 0x00

#define TRUE 1
#define FALSE 0

typedef struct _R_datalib_parm_list_64 { 
	int num_parms;
    double workarea[128];  // double word aligned, 1024 bytes long workarea
    int saf_rc_ALET, return_code;
    int racf_rc_ALET, RACF_return_code;
    int racf_rsn_ALET, RACF_reason_code;
    char function_code;
    int  attributes;
    char RACF_userid_len; // DO NOT change position of this field
    char RACF_userid[MAX_USERID_LEN];  // DO NOT change position of this field
    char ring_name_len;   // DO NOT change position of this field
    char ring_name[MAX_KEYRING_LEN];  // DO NOT change position of this field
    int  parm_list_version;
    void *parmlist;
} R_datalib_parm_list_64;

typedef struct _R_datalib_function {
	char name[MAX_FUNCTION_LEN];
    char code;
    int default_attributes;
    int parm_list_version;
    void *parmlist;
} R_datalib_function;

typedef _Packed struct _R_datalib_data_remove { // DO NOT change property positions in this struct
    int label_len;
    int reserved_1;
    char *label_addr;
    char CERT_userid_len;  
    char CERT_userid[MAX_USERID_LEN];   
    char reserved_2[3];
} R_datalib_data_remove;

typedef struct _Data_get_buffers {
    int certificate_length;
    char certificate[MAX_CERTIFICATE_LEN];
    int private_key_length;
    char private_key[MAX_PRIVATE_KEY_LEN];
    int label_length;
    char label[MAX_LABEL_LEN + 1];
    int subject_DN_length;
    char subject_DN[MAX_SUBJECT_DN_LEN];
    char record_id[MAX_RECORD_ID_LEN];
} Data_get_buffers;

typedef struct _Return_codes {
    char function_code;
    int SAF_return_code;
    int RACF_return_code;
    int RACF_reason_code;
} Return_codes;

typedef _Packed struct _R_datalib_result_handle { // DO NOT change property positions in this struct
    int dbToken;
    int number_predicates;
    int attribute_id;
    int attribute_length;
    char *attribute_ptr; 
} R_datalib_result_handle;

typedef _Packed struct _R_datalib_data_get { // DO NOT change property positions in this struct
    R_datalib_result_handle *handle;
    int certificate_usage;
    int Default;
    int certificate_len;
    int reserved_1;
    char *certificate_ptr;
    int private_key_len;
    int reserved_2;
    char *private_key_ptr;
    int private_key_type;
    int private_key_bitsize;
    int label_len;
    int reserved_3;
    char *label_ptr;
    char cert_userid_len;  
    char cert_userid[MAX_USERID_LEN];
    char reserved_4[3];
    int subjects_DN_length;
    char *subjects_DN_ptr;
    int record_ID_length;
    int reserved_5;
    char *record_ID_ptr;
    int certificate_status;
} R_datalib_data_get;

typedef _Packed struct _R_datalib_data_abort {
    R_datalib_result_handle *handle;
} R_datalib_data_abort;

typedef _Packed struct _R_datalib_data_put { // DO NOT change property positions in this struct
    int certificate_usage;
    int Default;
    int certificate_len;
    int reserved_1;
    char *certificate_ptr;
    int private_key_len;
    int reserved_2;
    char *private_key_ptr;
    int label_len;
    int reserved_3;
    char *label_ptr;
    char cert_userid_len;  
    char cert_userid[MAX_USERID_LEN];
    char reserved_4[3];
} R_datalib_data_put;

void invoke_R_datalib(R_datalib_parm_list_64*);
void set_up_R_datalib_parameters(R_datalib_parm_list_64* , R_datalib_function* , char* ,char* );
void dump_certificate_and_key(Data_get_buffers*);

static PyObject* throwRdatalibException(int, int, int, int);
static PyObject* check_return_code(R_datalib_parm_list_64*);
#endif
