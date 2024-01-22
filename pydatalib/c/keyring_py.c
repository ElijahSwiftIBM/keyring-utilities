/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
*/

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "keyring_get.h"

#define MSG_BUF_LEN 256
#define GET_DATA_NUM_ARG 4
#define LIST_KEYRING_NUM_ARG 2
#define MAX_FORMAT_LEN 3

#define _STRINGIFY(s) #s
#define STRINGIFY(s) _STRINGIFY(s)

// Function to pass return codes back to caller as pyobject for error handling
static PyObject* throwRdatalibException(int function, int safRC, int racfRC, int racfRSN ) {
  return Py_BuildValue(
    "{s:B,s:B,s:B,s:B}",
    "functionCode", function,
    "safReturnCode", safRC,
    "racfReturnCode", racfRC,
    "racfReasonCode", racfRSN
  );
}

// Function to check return codes and throw an RdatalibException on any failure
static PyObject* check_return_code(R_datalib_parm_list_64* p) {
    if (p->return_code != 0 || p->RACF_return_code != 0 || p->RACF_reason_code != 0) {
        return throwRdatalibException(p->function_code, p->return_code, p->RACF_return_code, p->RACF_reason_code);
    }
    else {
        return Py_BuildValue("b", 0);
    }
}

// Entry point to the getData() function
static PyObject* getData(PyObject* self, PyObject* args, PyObject *kwargs) {
  const char * userid_in, * keyring_in, * label_in;
  char userid[MAX_USERID_LEN + 1] = "";
  char keyring[MAX_KEYRING_LEN + 1] = "";
  char label[MAX_LABEL_LEN + 1] = "";
  PyObject *buffer_cert, *buffer_key;

  static char *kwlist[] = {"userid", "keyring", "label", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|yyy", kwlist, &userid_in, &keyring_in, &label_in)) {
      return NULL;
  }

  strncpy(&userid, userid_in, MAX_USERID_LEN);
  strncpy(&keyring, keyring_in, MAX_KEYRING_LEN);
  strncpy(&label, label_in, MAX_LABEL_LEN);

  Data_get_buffers buffers;
  memset(&buffers, 0x00, sizeof(Data_get_buffers));
  Return_codes ret_codes;

  get_data(userid, keyring, label, &buffers, &ret_codes);
  if (ret_codes.SAF_return_code != 0) {
    return throwRdatalibException(ret_codes.function_code, ret_codes.SAF_return_code,
                           ret_codes.RACF_return_code, ret_codes.RACF_reason_code);
  }

  return Py_BuildValue(
    "{s:y#,s:y#}",
    "certificate", buffers.certificate, buffers.certificate_length,
    "privateKey", buffers.private_key, buffers.private_key_length
  );
}

void resetGetParm(R_datalib_data_get *getParm) {
  getParm->certificate_len = MAX_CERTIFICATE_LEN;
  getParm->private_key_len = MAX_PRIVATE_KEY_LEN;
  getParm->label_len = MAX_LABEL_LEN;
  getParm->subjects_DN_length = MAX_SUBJECT_DN_LEN;
  getParm->record_ID_length = MAX_RECORD_ID_LEN;
  getParm->cert_userid_len = 0x08;
}

int lengthWithoutTralingSpaces(char *str, int maxlen) {
  char *end = str + maxlen - 1;
  while (end >= str && *end == 0x40) end--;
  return end - str + 1;
}

// Build a python dictionary with cert information from current certificate
PyObject *getCertItem(R_datalib_data_get *getParm) {
  char *usage, *status;
  int certUserLen;

  certUserLen = lengthWithoutTralingSpaces(getParm->cert_userid, 8);

  switch (getParm->certificate_usage) {
    case 0x00000008:
      usage = "PERSONAL";
      break;
    case 0x00000002:
      usage = "CERTAUTH";
      break;
    default:
      usage = "OTHER";
  }

  switch (getParm->certificate_status) {
    case 0x80000000:
      status = "TRUST";
      break;
    case 0x40000000:
      status = "HIGHTRUST";
      break;
    case 0x20000000:
      status = "NOTRUST";
      break;
    default:
      status = "UNKNOWN";
  }

  return Py_BuildValue(
    "{s:y#,s:y#,s:s,s:s,s:i,s:y#}",
    "label", getParm->label_ptr, getParm->label_len,
    "owner", getParm->cert_userid, certUserLen, "usage", usage,
    "status", status, "default", getParm->Default,
    "certificate", getParm->certificate_ptr, getParm->certificate_len
  );

}

// Entry point to the listKeyring() function
static PyObject* listKeyring(PyObject* self, PyObject* args, PyObject *kwargs) {
  const char *userid_in, *keyring_in;
  char userid[MAX_USERID_LEN + 1] = "";
  char keyring[MAX_KEYRING_LEN + 1] = "";

  static char *kwlist[] = {"userid", "keyring", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|yy", kwlist, &userid_in, &keyring_in)) {
      return NULL;
  }

  strncpy(&userid, userid_in, MAX_USERID_LEN);
  strncpy(&keyring, keyring_in, MAX_KEYRING_LEN);

  int origMode;
  int rc = 0;
  Data_get_buffers buffers;
  R_datalib_parm_list_64 parms;
  R_datalib_data_get getParm;
  R_datalib_result_handle handle;
  R_datalib_data_abort dataAbort;

  R_datalib_function getFirstFunc = {"", GETCERT_CODE, 0x80000000, 1, &getParm};
  R_datalib_function getNextFunc = {"", GETNEXT_CODE, 0x80000000, 1, &getParm};
  R_datalib_function abortFunc = {"", DATA_ABORT_CODE, 0x00000000, 0, &dataAbort};

  memset(&buffers, 0x00, sizeof(Data_get_buffers));
  memset(&getParm, 0x00, sizeof(R_datalib_data_get));
  memset(&handle, 0x00, sizeof(R_datalib_result_handle));

  getParm.handle = &handle;
  getParm.certificate_ptr = buffers.certificate;
  getParm.private_key_ptr = buffers.private_key;
  getParm.label_ptr = buffers.label;
  getParm.subjects_DN_ptr = buffers.subject_DN;
  getParm.record_ID_ptr = buffers.record_id;
  // X'80000000' = TRUST; X'40000000' = HIGHTRUST; X'20000000' = NOTRUST; X'00000000' = ANY
  getParm.certificate_status = 0x00000000;

  PyObject *cert_array;
  cert_array = PyList_New(1);

  resetGetParm(&getParm);
  set_up_R_datalib_parameters(&parms, &getFirstFunc, userid, keyring);
  invoke_R_datalib(&parms);

  if (parms.return_code != 0) {
    return throwRdatalibException(parms.function_code, parms.return_code, parms.RACF_return_code, parms.RACF_reason_code);
  }

  PyList_SetItem(cert_array, 0, getCertItem(&getParm));

  int i = 1;
  while (1) {

    resetGetParm(&getParm);
    set_up_R_datalib_parameters(&parms, &getNextFunc, userid, keyring);
    invoke_R_datalib(&parms);

    if (parms.return_code == 8 && parms.RACF_return_code == 8 && parms.RACF_reason_code == 44) { // No more cert found;
      break;
    }
    else if (parms.return_code != 0) {
      return throwRdatalibException(parms.function_code, parms.return_code, parms.RACF_return_code, parms.RACF_reason_code);
    }
    else {
      PyList_Append(cert_array, getCertItem(&getParm));
    }
  }

  dataAbort.handle = &handle;
  set_up_R_datalib_parameters(&parms, &abortFunc, userid, keyring);
  invoke_R_datalib(&parms);

  return cert_array;
}

// Entry point to the dataRemove() function
static PyObject* dataRemove(PyObject* self, PyObject* args, PyObject *kwargs) {
    const char * userid_in, * keyring_in, * label_in;
    char userid[MAX_USERID_LEN + 1] = "";
    char keyring[MAX_KEYRING_LEN + 1] = "";
    char label[MAX_LABEL_LEN + 1] = "";
    PyObject *buffer_cert, *buffer_key;

    static char *kwlist[] = {"userid", "keyring", "label", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|yyy", kwlist, &userid_in, &keyring_in, &label_in)) {
        return NULL;
    }

    strncpy(&userid, userid_in, MAX_USERID_LEN);
    strncpy(&keyring, keyring_in, MAX_KEYRING_LEN);
    strncpy(&label, label_in, MAX_LABEL_LEN);

    R_datalib_function func;
    R_datalib_parm_list_64 *rdatalib_parms;

    R_datalib_data_remove rem_parm;
    memset(&rem_parm, 0x00, sizeof(R_datalib_data_remove));

    R_datalib_function dataRemoveFunc = {"DATAREMOVE", DATAREMOVE_CODE, 0x00000000, 0, &rem_parm};


    rem_parm.label_len = strlen(label);
    rem_parm.label_addr = label;
    rem_parm.CERT_userid_len = strlen(userid);
    memset(rem_parm.CERT_userid, ' ', MAX_USERID_LEN); // fill the CERT_userid field with blanks
    memcpy(rem_parm.CERT_userid, userid, rem_parm.CERT_userid_len);

    set_up_R_datalib_parameters(rdatalib_parms, &dataRemoveFunc, userid, keyring);
    invoke_R_datalib(rdatalib_parms);
    return check_return_code(rdatalib_parms);
}

// Entry point to the touchKeyring() function
static PyObject* touchKeyring(PyObject* self, PyObject* args, PyObject *kwargs) {
    const char * userid_in, * keyring_in, * function_code;
    char userid[MAX_USERID_LEN + 1] = "";
    char keyring[MAX_KEYRING_LEN + 1] = "";
    PyObject *buffer_cert, *buffer_key;

    static char *kwlist[] = {"userid", "keyring", "function_code", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|yyb", kwlist, &userid_in, &keyring_in, &function_code)) {
        return NULL;
    }

    strncpy(&userid, userid_in, MAX_USERID_LEN);
    strncpy(&keyring, keyring_in, MAX_KEYRING_LEN);

    R_datalib_function *func;
    R_datalib_parm_list_64 *rdatalib_parms;

    R_datalib_function newRingFunc = {"NEWRING", NEWRING_CODE, 0x00000000, 0, NULL};
    R_datalib_function refreshFunc = {"REFRESH", REFRESH_CODE, 0x00000000, 0, NULL};
    R_datalib_function delRingFunc = {"DELRING", DELRING_CODE, 0x00000000, 0, NULL};

    switch(function_code){
        case NEWRING_CODE:
            func = &newRingFunc;
            break;
        case REFRESH_CODE:
            func = &refreshFunc;
            break;
        case DELRING_CODE:
            func = &delringFunc;
            break;
        default:
            printf("Error: invalid function code for touchKeyring");
            return throwRdatalibException(functionCode,12,12,12);
    }
    set_up_R_datalib_parameters(rdatalib_parms, func, userid, keyring);
    invoke_R_datalib(rdatalib_parms);
    return check_return_code(rdatalib_parms);
}

// Entry point to the dataPut() function
static PyObject* dataPut(PyObject* self, PyObject* args, PyObject *kwargs) {
    const char * userid_in, * keyring_in, * label_in, * cert_buff_in, * priv_key_in;
    char userid[MAX_USERID_LEN + 1] = "";
    char keyring[MAX_KEYRING_LEN + 1] = "";
    char label[MAX_LABEL_LEN + 1] = "";
    char cert_buff[MAX_CERTIFICATE_LEN + 1] = "";
    char priv_key[MAX_PRIVATE_KEY_LEN + 1] = "";

    static char *kwlist[] = {"userid", "keyring", "label", "certificate", "private_key", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|yyyyy", kwlist, &userid_in, &keyring_in, &label_in, &cert_buff_in, &priv_key_in)) {
        return NULL;
    }

    strncpy(&userid, userid_in, MAX_USERID_LEN);
    strncpy(&keyring, keyring_in, MAX_KEYRING_LEN);
    strncpy(&label, label_in, MAX_LABEL_LEN);
    strncpy(&cert_buff, cert_buff_in, MAX_CERTIFICATE_LEN);
    strncpu(&priv_key, priv_key_in, MAX_PRIVATE_KEY_LEN);

    R_datalib_function func;
    R_datalib_parm_list_64 *rdatalib_parms;

    R_datalib_data_put put_parm;
    memset(&put_parm, 0x00, sizeof(R_datalib_data_put));

    func = {"DATAPUT", DATAPUT_CODE, 0x00000000, 0, &put_parm};

    put_parm.Default = 0x00000000;
    put_parm.certificate_len = strlen(cert_buff);
    put_parm.certificate_ptr = cert_buff;
    put_parm.private_key_len = strlen(priv_key);
    put_parm.private_key_ptr = priv_key;
    put_parm.label_len = strlen(label);
    put_parm.label_ptr = label;
    put_parm.cert_userid_len = strlen(userid);
    memset(put_parm.cert_userid, ' ', MAX_USERID_LEN); // fill the cert_userid field with blanks
    memcpy(put_parm.cert_userid, userid, put_parm.cert_userid_len);

    set_up_R_datalib_parameters(rdatalib_parms, &func, userid, keyring);
    invoke_R_datalib(rdatalib_parms);
    return check_return_code(rdatalib_parms);
}

//Method docstrings
static char getDataDocs[] =
   "getData(userid, keyring, label): Obtains certificate data (including private key) and "
   "returns this information in a python dictionary. If R_datalib encounters a failure, "
   "returns return and reasoun codes from R_Datalib RACF Callable Service.\n";

static char listKeyringDocs[] =
   "listKeyring(userid, keyring): Obtains certificate data for all certificates on the "
   "keyring and returns this information in a list of python dictionaries. If R_datalib "
   "encounters a failure, returns return and reasoun codes from R_Datalib RACF Callable "
   "Service.\n";

static char dataRemoveDocs[] =
   "dataRemove(userid, keyring, label): Deletes the specified certificate from RACF. If "
   "R_datalib encounters a failure, returns return and reasoun codes from R_Datalib "
   "RACF Callable Service.\n";

static char touchKeyringDocs[] =
   "touchKeyring(userid, keyring, function_code): Touches a specific keyring to perform "
   "a specified function (x'07' Create this keyring, x'0B' Refresh this keyring, x'0A' "
   "Delete this keyring). If R_datalib encounters a failure, returns return and reason "
   "codes from R_Datalib RACF Callable Service.\n";

static char dataPutDocs[] =
   "dataPut(userid, keyring, label, certificate, private_key): Adds the specified "
   "certificate information to RACF with the spefified label. If R_datalib encounters "
   "a failure, returns return and reasoun codes from R_Datalib RACF Callable Service.\n";

// Method definition
static PyMethodDef cpydatalib_methods[] = {
   {"getData", (PyCFunction)getData,
      METH_VARARGS | METH_KEYWORDS, getDataDocs},
   {"listKeyring", (PyCFunction)listKeyring,
      METH_VARARGS | METH_KEYWORDS, listKeyringDocs},
   {"dataRemove", (PyCFunction)dataRemove,
      METH_VARARGS | METH_KEYWORDS, dataRemoveDocs},
   {"touchKeyring", (PyCFunction)touchKeyring,
      METH_VARARGS | METH_KEYWORDS, touchKeyringDocs},
   {"dataPut", (PyCFunction)dataPut,
      METH_VARARGS | METH_KEYWORDS, dataPutDocs},
  {NULL}
};

//Module definition
static struct PyModuleDef cpydatalib_module_def =
{
        PyModuleDef_HEAD_INIT,
        "cpydatalib", 
        "C code that enables pyRACF to call the R_datalib RACF callable service.\n",
        -1,
        cpydatalib_methods
};

//Module initialization function
PyMODINIT_FUNC PyInit_cpydatalib(void)
{
        Py_Initialize();
        return PyModule_Create(&cpydatalib_module_def);
}