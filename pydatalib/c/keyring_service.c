/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
* Copyright Contributors to the Zowe Project.                                     *
*/

#include <string.h>

#include "keyring_types.h"

#ifdef _LP64
    #pragma linkage(IRRSDL64, OS)
#else
    #error "31-bit not supported yet."
#endif 

void invoke_R_datalib(R_datalib_parm_list_64 * p) {

    IRRSDL64(
                &p->num_parms,
                &p->workarea,
                &p->saf_rc_ALET, &p->return_code,
                &p->racf_rc_ALET, &p->RACF_return_code,
                &p->racf_rsn_ALET, &p->RACF_reason_code,
                &p->function_code,
                &p->attributes,
                &p->RACF_userid_len,
                &p->ring_name_len,
                &p->parm_list_version,
                p->parmlist
            );
}

void set_up_R_datalib_parameters(R_datalib_parm_list_64 * p, R_datalib_function * function, char * userid, char * keyring) {
    printf("entered setting up parms\n");
    memset(p, 0, sizeof(R_datalib_parm_list_64));
    printf("through the first memset\n");
    p->num_parms = 14;
    p->saf_rc_ALET = 0;
    p->racf_rc_ALET = 0;
    p->racf_rsn_ALET = 0;
    p->function_code = function->code;
    p->attributes = function->default_attributes;
    printf("through preliminary initializations\n");
    memset(&p->RACF_userid_len, strlen(userid), 1);
    printf("did user id len\n");
    memcpy(p->RACF_userid, userid, strlen(userid));
    printf("did actual user id\n");
    memset(&p->ring_name_len, strlen(keyring), 1);
    printf("did ring name len\n");
    memcpy(p->ring_name, keyring, strlen(keyring));
    printf("through all other memsets\n");
    p->parm_list_version = function->parm_list_version;
    p->parmlist = function->parmlist;
}