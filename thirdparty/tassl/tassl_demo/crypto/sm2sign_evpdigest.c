/*
 * Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"

int main(int argc, char *argv[])
{
    EVP_PKEY *sm2key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *out = NULL;
    size_t len;
    int loop;
    
    
    if (argc < 2)
    {
        printf("Usage: %s testmessage\n", argv[0]);
        exit(0);
    }
    
    OpenSSL_add_all_algorithms();

    /*First Generate SM2 Key*/
    sm2key = EVP_PKEY_new();
    if (!sm2key)
    {
        printf("Alloc EVP_PKEY Object error.\n");
        goto err;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx)
    {
        printf("Create EVP_PKEY_CTX Object error.\n");
        goto err;
    }
    
    EVP_PKEY_keygen_init(pctx);
    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2))
    {
        printf("Set EC curve name error.\n");
        goto err;
    }
    
    if (!EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE))
    {
        printf("Set EC curve is named curve error.\n");
        goto err;
    }
    
    if (EVP_PKEY_keygen(pctx, &sm2key) <= 0)
    {
        printf("Generate SM2 key error.\n");
        goto err;
    }
    
    /*OUTPUT EVP PKEY*/
    len = i2d_PrivateKey(sm2key, &out);
    if (len <= 0)
    {
        printf("Output SM2 Private Key Error.\n");
        goto err;
    }
    
    printf("Generated SM2 Key: [");
    for (loop = 0; loop < len; loop++)
        printf("%02X", out[loop] & 0xff);
    printf("]\n");

    len = EVP_PKEY_size(sm2key);
    if (out) OPENSSL_free(out);
    out = OPENSSL_malloc(len);
    if (!out)
    {
        printf("Alloc Memory Error.\n");
        goto err;
    }

    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx)
    {
        printf("Error of Create EVP_MD_CTX Object Error.\n");
        goto err;
    }
    
    EVP_MD_CTX_init(md_ctx);
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, sm2key) <= 0)
    {
        printf("Init DigestSign CTX Error.\n");
        goto err;
    }
    
    EVP_DigestSignUpdate(md_ctx, argv[1], strlen(argv[1]));
    EVP_DigestSignFinal(md_ctx, out, &len);
    
    printf("[%s] SM2 Signature: [", argv[1]);
    for (loop = 0; loop < len; loop++)
        printf("%02X", out[loop] & 0xff);
    printf("]\n");
    
    EVP_MD_CTX_destroy(md_ctx);
    
    /*Now Verify It*/
    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx)
        goto err;
    
    EVP_MD_CTX_init(md_ctx);
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, sm2key) <= 0)
    {
        printf("Init DigestVerify CTX Error.\n");
        goto err;
    }
    
    EVP_DigestVerifyUpdate(md_ctx, argv[1], strlen(argv[1]));
    loop = EVP_DigestVerifyFinal(md_ctx, (const unsigned char *)out, len);
    if (loop <= 0)
    {
        printf("EVP_DigestVerify Error.\n");
    }
    else
    {
        printf("EVP_DigestVerify Successed.\n");
    }
    
err:
    if (sm2key) EVP_PKEY_free(sm2key);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
    if (out) OPENSSL_free(out);

    return 0;
}
