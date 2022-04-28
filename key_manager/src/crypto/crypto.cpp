//
// Created by edward on 4/25/22.
//

#include <crypto.h>
#include <../utils.h>
#include <log.h>
#include <openssl/sm3.h>
#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <TassAPI4EHVSM.h>
#include <iostream>
#include <sstream>
//
namespace datacloak{

    std::map<std::string, std::string> Crypto::key_map_;

    std::string Crypto::sm3_hash(const std::string &msg) {
        unsigned char hash[SM3_DIGEST_LENGTH] = {0};
        char out[SM3_DIGEST_LENGTH * 2 + 1] = {0};
        SM3_CTX ctx;
        int ret = sm3_init(&ctx);
        if(ret != 1){
            LOG(INFO) << "sm3_init error, errno[" << ERR_get_error << "]";
            return "";
        }
        ret = sm3_update(&ctx, msg.c_str(), msg.length());
        if(ret != 1){
            LOG(INFO) << "sm3_update error, errno[" << ERR_get_error << "]";
            return "";
        }
        ret = sm3_final(hash, &ctx);
        if(ret != 1){
            LOG(INFO) << "sm3_final error, errno[" << ERR_get_error() << "]";
            return "";
        }
        for(int i = 0; i < SM3_DIGEST_LENGTH; i++){
            sprintf(out + (i * 2), "%02x", hash[i]);
        }
        return std::string{out};
    }

    std::string Crypto::SM2_sign(const char* key_index, const std::string &data) {
        SSL_library_init();
        SSL_load_error_strings();
        ENGINE *engine = ENGINE_by_id(ENGINE_NAME);
        EVP_PKEY *pkey = nullptr;
        std::string signature = "";
        unsigned char *sign_temp = nullptr;

        do{
#if 1
            EC_GROUP *group = nullptr;
            EC_KEY *test_key = nullptr;
            group = EC_GROUP_new_by_curve_name(NID_sm2);
            if(!group){
                ERR_print_errors_fp(stderr);
                break;
            }
            test_key = EC_KEY_new();
            if(!test_key){
                ERR_print_errors_fp(stderr);
                break;
            }
            if(EC_KEY_set_group(test_key,(const EC_GROUP*)group) == 0){
                ERR_print_errors_fp(stderr);
                break;
            }
            if(EC_KEY_generate_key(test_key) == 0){
                ERR_print_errors_fp(stderr);
                break;
            }
#endif
            if(!engine){
                LOG(ERROR) << "ENGINE_by_id error, errno[" << ERR_get_error() << "]";
                ERR_print_errors_fp(stderr);
                break;
            }
            int err = ENGINE_init(engine);
            if(err != 1){
                LOG(ERROR) << "ENGINE_init error";
                ERR_print_errors_fp(stderr);
                break;
            }
            pkey = ENGINE_load_private_key(engine, key_index, nullptr, nullptr);
            if(!pkey){
                LOG(ERROR) << "ENGINE_load_private_key error";
                ERR_print_errors_fp(stderr);
                break;
            }

            EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
            if(!ec_key){
                LOG(ERROR) << "EVP_PKEY_get1_EC_KEY error";
                break;
            }
            ECDSA_SIG *sign = sm2_do_sign(ec_key, EVP_sm3(),
                                          reinterpret_cast<const uint8_t *>(SM2_DEFAULT_USERID),
                                          strlen(SM2_DEFAULT_USERID),
                                          reinterpret_cast<const uint8_t *>(data.c_str()),
                                          data.length());
            if(!sign){
                LOG(ERROR) << "sm2_do_sign error";
                break;
            }
            sign_temp = (unsigned char*)OPENSSL_malloc(1024);
            if(!sign_temp){
                LOG(ERROR) << "OPENSSL_malloc failed\n";
                break;
            }
            int length = i2d_ECDSA_SIG(sign, &sign_temp);
            if(length == 0){
                LOG(ERROR) << "i2d_ECDSA_SIG error";
            }
            for(int i = 0; i < length; i++){
                printf("%02X", (uint8_t)sign_temp[i]);
            }
            printf("\n");
            LOG(INFO) << "sign_temp[" <<sign_temp << "]\n";
            signature = ECDSA_SIG_to_string(sign);
            LOG(INFO) << "signature[" << signature << "]\n";
        } while (false);
        if(engine){
            ENGINE_free(engine);
        }

        if(pkey){
            EVP_PKEY_free(pkey);
        }
        if(sign_temp){
            //OPENSSL_free(sign_temp);
        }
        return signature;
    }

    std::string Crypto::SM2_sign(const std::string &key_index, const std::string& hash) {
        EC_KEY *sm2_key = nullptr;
        BIO *bio = nullptr;
#if 0
        EC_GROUP *sm2group = NULL;
#endif
        bool signed_done = true;
        unsigned char sign[32] = {0};
        unsigned int sign_len = sizeof(sign);
#if 0
        unsigned char Z[SM3_DIGEST_LENGTH] = {0};
        size_t Z_len = sizeof(Z);
#endif
        do{
#if 0
            sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
            if(!sm2group){
                LOG(ERROR) << "EC_GROUP_new_by_curve_name error";
                signed_done = false;
                break;
            }

            bio = BIO_new(BIO_s_mem());
            if(!bio){
                LOG(ERROR) << "BIO_new_mem_buf error";
                signed_done = false;
                break;
            }

            PEM_read_bio_ECPrivateKey(bio, &sm2_key,NULL, NULL);

            int ret = EC_KEY_set_group(sm2_key, (const EC_GROUP*)sm2group);
            if(ret == 0){
                LOG(ERROR) << "EC_KEY_set_group error.";
                signed_done = false;
                break;
            }
            ret = EC_KEY_generate_key(sm2_key);
            if(ret == 0){
                LOG(ERROR) << "EC_KEY_generate_key error.";
                signed_done = false;
                break;
            }
#endif
#if 0
            ret = ECDSA_sm2_get_Z((const EC_KEY*)sm2_key, NULL, NULL, 0, Z, &Z_len);
            if (ret == 0){
                LOG(ERROR) << "ECDSA_sm2_get_Z error.";
                signed_done = false;
                break;
            }

            ret = sm2_compute_z_digest((uint8_t*)Z, EVP_sm3(), reinterpret_cast<const uint8_t *>(SM2_DEFAULT_USERID), strlen(SM2_DEFAULT_USERID), sm2_key);

            if(ret == 0){
                LOG(ERROR) << "sm2_compute_z_digest error.";
                signed_done = false;
                break;
            }
            Z_len = EVP_MD_size(EVP_sm3());
#endif

            int ret = sm2_sign((unsigned char *)hash.c_str(), hash.length(),sign, &sign_len, sm2_key);
            if(ret == 0){
                LOG(ERROR) << "sm2_sign error.";
                signed_done = false;
                break;
            }
        } while (false);
        if(bio){
            BIO_free(bio);
        }

        if(!signed_done){
            return "";
        }else{
            return std::string{(char*)sign};
        }
    }

    void Crypto::GenerateECCKey() {
        EC_KEY *key = nullptr;
        BIO *bio = nullptr;
        char private_key[2048] = {0};
        do{
            key = EC_KEY_new_by_curve_name(NID_sm2);
            if(!key){
                LOG(ERROR) << "EC_KEY_new failed";
                break;
            }
            int ret = EC_KEY_generate_key(key);
            if(ret == 0){
                LOG(ERROR) << "EC_KEY_generate_key failed";
                break;
            }
            bio = BIO_new(BIO_s_mem());
            if(!bio){
                LOG(ERROR) << "BIO_new failed";
                break;
            }

            ret = PEM_write_bio_ECPrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
            if(ret == 0){
                LOG(ERROR) << "PEM_write_bio_ECPrivateKey failed";
                break;
            }
            BUF_MEM *buf = nullptr;
            BIO_get_mem_ptr(bio, &buf);
            memcpy(private_key, buf->data, buf->length);
            std::cout << "Private key:\n" << private_key << "\n";
            key_map_.insert({"1", std::string{private_key}});
        } while (false);

        if(key){
            EC_KEY_free(key);
        }
        if(bio){
            BIO_free(bio);
        }
    }

    std::string Crypto::ECDSA_SIG_to_string(const void *sig) {
        const ECDSA_SIG *sign = (const ECDSA_SIG*)sig;
        const BIGNUM *r = ECDSA_SIG_get0_r(sign);
        const BIGNUM *s = ECDSA_SIG_get0_s(sign);
        if(!r || !s){
            LOG(ERROR) << "get bignum from SIG error";
            return "";
        }
        const char* rstr = BN_bn2hex(r);
        const char* sstr = BN_bn2hex(s);
        if(!rstr || !sstr){
            LOG(ERROR) << "convert big num to string error";
            return "";
        }

        std::string signature_str = std::string{rstr} + std::string{sstr};
        OPENSSL_free((void*)rstr);
        OPENSSL_free((void*)sstr);
        return signature_str;
#if 0
        degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
        LOG(INFO) << "EC_GROUP_get_degree[" << degree << "]";
        if(degree < 160){

        }
        r_len = BN_num_bytes(r);
        s_len = BN_num_bytes(s);
        bn_len = (degree + 7) / 8;
        buf_len = 2 * bn_len;
#endif

    }

    std::string Crypto::SM2_sign_with_sm3(const std::string &data) {
        char *index = "55";
        char *tag = "ymx-55";
        char *public_key_der = nullptr;
        char *private_key_cipher_by_lmk = nullptr;

        // generate key pair
        int err = driverE7_GenerateSM2KeyPair(index, tag, reinterpret_cast<FRM_INT8_PTR *>(&public_key_der),
                                              reinterpret_cast<FRM_INT8_PTR *>(&private_key_cipher_by_lmk));
        if(err){
            LOG(ERROR) << "driverE7_GenerateSM2KeyPair failed";
            return "";
        }
        LOG(INFO) << "driverE7_GenerateSM2KeyPair succeed";
        printf("public_key_der: \n%s\n", public_key_der);
        printf("private_key_cipher_by_lmk: \n%s\n", private_key_cipher_by_lmk);

        // get public key
        //driverE2_GetSM2PublicKey()

        // sign data by sm2
        char *signature = nullptr;
#if 0
		char *data_hex = (char*)malloc(data.length() * 2 + 1);
		if(!data_hex){
			LOG(ERROR) << "malloc error, msg:[" << strerror(errno) << "]";
			return "";
		}
		memset(data_hex, 0, data.length() * 2 + 1);
		for(int i = 0; i < data.length(); i++){
			sprintf(data_hex + (i * 2), "%02X", (uint8_t)data.c_str()[i]);
		}
#endif
		std::string hash = sm3_hash(data);
#if 0
        err = driverE5_SM2PrivateKeySign(
                "",
                hash.c_str(),
                index,
                public_key_der,
                private_key_cipher_by_lmk,
                "1",
                &signature);
        if(err){
            LOG(ERROR) << "driverE5_SM2PrivateKeySign failed, errno[" << err << "]";
            return "";
        }
        LOG(INFO) << "driverE5_SM2PrivateKeySign succeed";
#endif
		driverED_SM2PrivateKeySignWithDataDigest(
					(char*)hash.c_str(),
					index,
					"0",
					&signature
				);
        if(err){
            LOG(ERROR) << "driverED_SM2PrivateKeySignWithDataDigest failed, errno[" << err << "]";
            return "";
        }
        LOG(INFO) << "driverED_SM2PrivateKeySignWithDataDigest succeed";
		std::cout << "hash:" << hash << "\n";
        printf("signature:%s\n",signature);
		err = driverEF_SM2PublicKeyVerifyWithDataDigest(
				"0",
				signature,
				(char*)hash.c_str(),
				index
				);
		if(err != 0){
			LOG(ERROR) << "driverEF_SM2PublicKeyVerifyWithDataDigest failed, errno[" << err << "]";
			return "";
		}
		LOG(INFO) << "driverEF_SM2PublicKeyVerifyWithDataDigest succeed";
        return std::string{signature};
    }

    std::string Crypto::SM2_Encrypt(const std::string& msg, const std::string& pub_key_idx) {
        char *cipher = NULL;

        char *data_hex = (char*)malloc(msg.length() * 2 + 1);
        if(!data_hex){
            LOG(ERROR) << "malloc error, msg:[" << strerror(errno) << "]";
            return "";
        }
        memset(data_hex, 0, msg.length() * 2 + 1);
        for(int i = 0; i < msg.length(); i++){
            sprintf(data_hex + (i * 2), "%02X", (uint8_t)msg.c_str()[i]);
        }
        /*for (int idx = 0; idx < msg.length() * 2 + 1; ++idx) {
            std::cout << data_hex[idx];
        }
        std::cout << std::endl;*/

        size_t key_len = pub_key_idx.length();
        char key_cstr[key_len + 1];
        memset(key_cstr, 0, key_len + 1);
        memcpy(key_cstr, pub_key_idx.c_str(), key_len);

        int result = driverE3_SM2PublicKeyEncrypt(data_hex, key_cstr, &cipher);
        free(data_hex);
        if (0 != result) {
            LOG(ERROR) << "driverE3_SM2PublicKeyEncrypt failed, errno[" << result << "]";
            return "";
        }
        else {
            std::string ret_s(cipher);
            driver_Free(&cipher);
            return ret_s;
        }
    }

    std::string Crypto::SM2_Decrypt(const std::string& msg, const std::string& pri_key_idx) {
        char *text = NULL;

        size_t msg_len = msg.length();
        char msg_cstr[msg_len + 1];
        memset(msg_cstr, 0, msg_len + 1);
        memcpy(msg_cstr, msg.c_str(), msg_len);

        size_t key_len = pri_key_idx.length();
        char key_cstr[key_len + 1];
        memset(key_cstr, 0, key_len + 1);
        memcpy(key_cstr, pri_key_idx.c_str(), key_len);

        int result = driverE4_SM2PrivateKeyDecrypt(msg_cstr, key_cstr, &text);
        if (0 != result) {
            LOG(ERROR) << "driverE3_SM2PrivateKeyDecrypt failed, errno[" << result << "]";
            return "";
        }
        else {
            std::string ret_s(text);
            driver_Free(&text);
            return ret_s;
        }
    }
}
