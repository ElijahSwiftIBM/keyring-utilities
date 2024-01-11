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
    "SafReturnCode", safRC,
    "RacfReturnCode", racfRC,
    "RacfReasonCode", racfRSN
  );
}

// Entry point to the getData() function
static PyObject* getData(PyObject* self, PyObject* args, PyObject *kwargs) {
  const char * userid_in, keyring_in, label_in;
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

  printf("Passed userid:  '%s' | Length: '%d'\nCurrent userid:  '%s' | Length: '%d'\n", userid_in, strlen(userid_in), userid, strlen(userid));
  printf("Passed keyring: '%s' | Length: '%d'\nCurrent keyring: '%s' | Length: '%d'\n", keyring_in, strlen(keyring_in), keyring, strlen(keyring));
  printf("Passed label:   '%s' | Length: '%d'\nCurrent label:   '%s' | Length: '%d'\n", label_in, strlen(label_in), label, strlen(label));
  printf("Maximum userid length: '%d\nMaximum keyring length: '%d'\nMaximum label length: '%d'\n", MAX_USERID_LEN, MAX_KEYRING_LEN, MAX_LABEL_LEN);

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

  printf("Passed userid:  '%s' | Length: '%d'\nCurrent userid:  '%s' | Length: '%d'\n", userid_in, strlen(userid_in), userid, strlen(userid));
  printf("Passed keyring: '%s' | Length: '%d'\nCurrent keyring: '%s' | Length: '%d'\n", keyring_in, strlen(keyring_in), keyring, strlen(keyring));
  printf("Maximum userid length: '%d\nMaximum keyring length: '%d'\n", MAX_USERID_LEN, MAX_KEYRING_LEN);

  int origMode;
  int rc = 0;
  Data_get_buffers buffers;
  R_datalib_parm_list_64 parms;
  R_datalib_data_get getParm;
  R_datalib_result_handle handle;
  R_datalib_data_abort dataAbort;

  R_datalib_function getFirstFunc = {"", GETCERT_CODE, 0x80000000, 1, &getParm, NULL};
  R_datalib_function getNextFunc = {"", GETNEXT_CODE, 0x80000000, 1, &getParm, NULL};
  R_datalib_function abortFunc = {"", DATA_ABORT_CODE, 0x00000000, 0, &dataAbort, NULL};

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

//Method docstrings
static char getDataDocs[] =
   "getData(): Returns something and return and reason codes from the R_Datalib RACF Callable Service.\n";

static char listKeyringDocs[] =
   "listKeyring(): Returns something and return and reason codes from the R_Datalib RACF Callable Service.\n";

// Method definition
static PyMethodDef pykeyring_methods[] = {
   {"getData", (PyCFunction)getData,
      METH_VARARGS | METH_KEYWORDS, getDataDocs},
   {"listKeyring", (PyCFunction)listKeyring,
      METH_VARARGS | METH_KEYWORDS, listKeyringDocs},
  {NULL}
};

//Module definition
static struct PyModuleDef pykeyring_module_def =
{
        PyModuleDef_HEAD_INIT,
        "pykeyring", 
        "C code that enables pyRACF to call the R_datalib RACF callable service.\n",
        -1,
        pykeyring_methods
};

//Module initialization function
PyMODINIT_FUNC PyInit_pykeyring(void)
{
        Py_Initialize();
        return PyModule_Create(&pykeyring_module_def);
}