
/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef NSPV_CCTX_H
#define NSPV_CCTX_H

// @blackjok3r and @mihailo implement the CC tx creation functions here

cJSON *NSPV_CC_faucetget()
{
    cJSON *result = cJSON_CreateObject();
    jaddstr(result,"result","error");
    jaddstr(result,"error","not implemented yet");
    jaddstr(result,"hex","deadbeef");
    jaddstr(result,"lastpeer",NSPV_lastpeer);
    return(result);
}
#endif // NSPV_CCTX_H
