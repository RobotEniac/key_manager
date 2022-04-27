/*
 * Written by Gujq for the TaSSL project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/engine.h"

int main(int argc, char *argv[])
{
    const EC_GROUP *group = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	unsigned char *out = NULL;
	size_t len;
	int loop;

    if (argc < 2)
    {
        printf("Usage: %s key_index\n", argv[0]);
        exit(0);
    }
    
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();
    
    /*111111 ��ʼ������*/
    const char *engine_name_sm2 = "tasscard_sm2";
    ENGINE *tasscardsm2_e = NULL;
    
    if ((tasscardsm2_e = ENGINE_by_id(engine_name_sm2)) == NULL) {
      printf("ENGINE load id=[%s] fail!\n", engine_name_sm2);
	  	exit(0);
    }
    else{
       ENGINE_init(tasscardsm2_e);
    }
    
    /*222222 ͨ��������������Կ�ԣ��������Ŵ���ڿ���*/
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, tasscardsm2_e);
	if (!pctx)
	{
		printf("Create EVP_PKEY_CTX Object error.\n");
		goto err;
	}
    
	EVP_PKEY_keygen_init(pctx);
	if (!EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(pctx, NID_sm2))
	{
		printf("Set EC curve name error.\n");
		goto err;
	}
    
	if (!EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE))
	{
		printf("Set EC curve is named curve error.\n");
		goto err;
	}
	
	EVP_PKEY_CTX_set_app_data(pctx, (void*)argv[1]);

	if (EVP_PKEY_keygen(pctx, &pkey) != 1)
	{
		printf("Generate SM2 key error.\n");
		goto err;
	}
	
	/*OUTPUT EVP PKEY*/
    len = i2d_PublicKey(pkey, &out);
    if (len <= 0)
    {
        printf("Output SM2 Public Key Error.\n");
        goto err;
    }
    
    printf("Generated SM2 PUB Key: [");
    for (loop = 0; loop < len; loop++)
        printf("%02X", out[loop] & 0xff);
    printf("]\n");
    

err:
	if (pkey) EVP_PKEY_free(pkey);
	if (pctx) EVP_PKEY_CTX_free(pctx);
	if (out) OPENSSL_free(out);
	    
    if(tasscardsm2_e){
        ENGINE_finish(tasscardsm2_e);
        ENGINE_free(tasscardsm2_e);
    }

	return 0;
}
