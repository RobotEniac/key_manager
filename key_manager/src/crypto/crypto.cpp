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
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/x509err.h>
#include <TassAPI4EHVSM.h>
#include <iostream>
//

#define BREAK_ERRNO(err,func) do{if((err)!= 1)  {ERR_print_errors_fp(stderr);LOG(ERROR) << func << " error"; err = -1;break;}else{LOG(INFO) << func << " succeed";}}while(false)
#define BREAK_NULL(x,msg) do{if((!x)) {ERR_print_errors_fp(stderr);LOG(ERROR) << msg; err = -1;break;}else{LOG(INFO) << msg << " succeed";}}while(false)

namespace datacloak{

    std::map<std::string, std::string> Crypto::key_map_;

    std::string Crypto::ca_cert;
    std::string Crypto::ca_private_key;
    std::string Crypto::private_key_index;

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

    void Crypto::GenerateECCKey(const std::string &index, std::string tag) {
        // generate key pair
        char *public_key_der = nullptr;
        char *private_key_cipher_by_lmk = nullptr;

        int err = driverE2_GetSM2PublicKey((char*)index.c_str(), &public_key_der);
        if(err == 0){
            LOG(INFO) << "driverE2_GetSM2PublicKey succeed";
            return;
        }else{
            LOG(ERROR) <<  "driverE2_GetSM2PublicKey failed";
        }

        err = driverE7_GenerateSM2KeyPair((char*)index.c_str(), (char*)tag.c_str(),
                                              reinterpret_cast<FRM_INT8_PTR *>(&public_key_der),
                                              reinterpret_cast<FRM_INT8_PTR *>(&private_key_cipher_by_lmk));
        if(err){
            LOG(ERROR) << "driverE7_GenerateSM2KeyPair failed";
            return;
        }
        LOG(INFO) << "driverE7_GenerateSM2KeyPair succeed";
        printf("public_key_der: \n%s\n", public_key_der);
        printf("private_key_cipher_by_lmk: \n%s\n", private_key_cipher_by_lmk);
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
    }

    bool Crypto::SM2_verify_with_sm3(const std::string &index, const std::string &sign, const std::string &msg) {
        std::string hash = sm3_hash(msg);
        int err = driverE6_SM2PublicKeyVerify(nullptr,
                                              "0",
                                              (char*)sign.c_str(),
                                              (char*)hash.c_str(),
                                              (char*)index.c_str());
        if(err != 0){
            LOG(ERROR) << "driverE6_SM2PublicKeyVerify failed, errno[" << err << "]";
            LOG(INFO) << "key_index[" << index <<"],sign["<< sign <<"],msg[" << msg <<"]";
            return false;
        }
        LOG(INFO) << "driverE6_SM2PublicKeyVerify succeed"<< "\nmsg[" << msg << "]\nhash[" << hash << "]\nsign[" << sign << "]";
        return true;
    }

    std::string Crypto::SM2_sign_with_sm3(const std::string &data,const std::string &key_index) {
        int err = 0;

        // sign data by sm2
        char *signature = nullptr;

		std::string hash = sm3_hash(data);
        char *index = (char*)key_index.c_str();
        char *chash = (char*)hash.c_str();
        err = driverE5_SM2PrivateKeySign(nullptr,
                                         chash ,
                                         index,
                                         nullptr,
                                         nullptr,
                                         "0",
                                         &signature);
        if(err){
            LOG(ERROR) << "driverE5_SM2PrivateKeySign failed, errno[" << err << "]";
            return "";
        }
        LOG(INFO) << "driverE5_SM2PrivateKeySign succeed";
        LOG(INFO) << "\norigin_data[" << data << "]\nhash[" << hash << "]\nsignature[" << signature <<"]";
        return std::string{signature};
    }


    void Crypto::SetRootKeys(const std::string& root_cert, const std::string& root_private_key) {
        ca_cert = root_cert;
        ca_private_key = root_private_key;
    }

    void Crypto::SetKeyIndex(std::string &index) {
        private_key_index = index;
    }
    int password(char * buff, int size, int rwflag, void* u){
        char *password = "start@2018";
        if(buff == NULL){
            return -1;
        }
        size_t len = strlen(password);
        if(len> size){
            len = size;
        }
        memcpy(buff, password, len);
        return len;
    }
    std::string Crypto::IssueGmCert(const std::string &pub, const std::string &name, bool use_engine, std::string key_index) {

        X509 *x509 = nullptr;
        EVP_PKEY *pk_ca = nullptr;
        EC_KEY *ec_key = nullptr;
        X509_NAME *x509_name = nullptr;
        std::string cert_str = "";
        ENGINE *engine = nullptr;
        bool engin_init_flag = false;
        int err = 0;
        do{
            pk_ca = EVP_PKEY_new();
            if(pk_ca == nullptr){
                std::cout << "EVP_PKEY_new error";
                break;
            }

            x509 = X509_new();
            if(x509 == nullptr){
                std::cout << "X509_new error";
                break;
            }
            if(!use_engine){
                BIO *ca_key_bio = BIO_new_mem_buf(ca_private_key.c_str(), -1);
                EC_KEY *ec_ca_key = PEM_read_bio_ECPrivateKey(ca_key_bio,  NULL, password, NULL);
                if(!ec_ca_key){
                    LOG(ERROR) << "read ca key failed";
                    break;
                }
                err = EVP_PKEY_assign_EC_KEY(pk_ca, ec_ca_key);
                if(err == 0){
                    std::cout << "EVP_PKEY_assign_EC_KEY error";
                    break;
                }
            }else{
                engine = ENGINE_by_id(ENGINE_NAME);
                BREAK_NULL(engine, "ENGINE_by_id");
                err = ENGINE_init(engine);
                BREAK_ERRNO(err, "ENGINE_init");
                engin_init_flag = true;
                pk_ca = ENGINE_load_private_key(engine, key_index.c_str(), nullptr, nullptr);
                BREAK_NULL(pk_ca, "ENGINE_load_private_key");
            }
            
            // read client pub key
            BIO *client_key_bio = BIO_new_mem_buf(pub.c_str(), -1);
            EC_KEY *ec_client_key = PEM_read_bio_EC_PUBKEY(client_key_bio,  NULL, NULL, NULL);
            if(!ec_client_key){
                LOG(ERROR) << "read ca key failed";
                break;
            }
            EVP_PKEY *client_pk = EVP_PKEY_new();
            EVP_PKEY_assign_SM2_KEY(client_pk, ec_client_key);

            X509_set_version(x509, 2);
            ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
            X509_gmtime_adj(X509_get_notBefore(x509), 0);
            X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 10240);
            X509_set_pubkey(x509, client_pk);



            BIO* ca_cert_bio = BIO_new_mem_buf(ca_cert.c_str(), -1);
            X509* root_certificate = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
            if(!root_certificate){
                LOG(ERROR) << "root certificate read error";
                break;
            }
            X509_NAME* issuer_name = X509_get_subject_name(root_certificate);
            X509_set_version(x509, 2);
            ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

            X509_gmtime_adj(X509_get_notBefore(root_certificate), 0);
            X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 365);

            X509_set_issuer_name(x509, issuer_name);
            x509_name = X509_get_subject_name(x509);

            X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("CN"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Guangdong"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Shenzhen"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("DataCloak"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("AUTH"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(name.c_str()), -1, -1, 0);

            add_ext(x509, NID_basic_constraints, const_cast<char *>("critical,CA:FALSE"));
            add_ext(x509, NID_ext_key_usage, const_cast<char *>("TLS Web Client Authentication,TLS Web Server Authentication "));
            add_ext(x509, NID_key_usage, const_cast<char *>("critical,Digital Signature,Certificate Sign,CRL Sign "));
            std::string alt_name = std::string{"DNS:"} + name + ",email:admin@datacloak.com";
            add_ext(x509, NID_subject_alt_name, const_cast<char *>(alt_name.c_str()));

            err = X509_sign(x509, pk_ca, EVP_sm3());
            if(err == 0){
                std::cout << "X509_sign error, errno[" << ERR_get_error()  << "], error msg[" <<
                          ERR_error_string(ERR_get_error(), NULL) << "]";

                break;
            }
            //EC_KEY_print_fp(stdout, EVP_PKEY_get0_EC_KEY(pk_ca), 0);
            //PEM_write_PrivateKey(stderr,pk_ca, nullptr, nullptr, 0, nullptr, nullptr);
            //PEM_write_X509(stderr, x509);
            BIO* client_cert_bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(client_cert_bio, x509);
            char cert_buf[102400] = {0};
            int len = BIO_read(client_cert_bio, cert_buf, 102400);
            cert_str.assign(cert_buf, cert_buf + len);
        } while (false);
        if(engine){
            if(engin_init_flag){
                ENGINE_finish(engine);
            }
            ENGINE_free(engine);
        }
        return cert_str;

    }

    int Crypto::add_ext(void *cert, int nid, char *value) {
        X509 *crt = (X509*)cert;
        X509_EXTENSION *ex;
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, crt, crt, nullptr, nullptr, 0);
        ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
        if(!ex){
            return 0;
        }
        X509_add_ext(crt, ex, -1);
        X509_EXTENSION_free(ex);
        return 1;
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
        for (int idx = 0; idx < msg.length() * 2 + 1; ++idx) {
            std::cout << data_hex[idx];
        }
        std::cout << std::endl;

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
            LOG(INFO) << "driverE3_SM2PublicKeyEncrypt:\n" << "original_msg[" << msg << "]\nencrypt_data[" << cipher << "]";
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
            char *data = (char*)malloc(strlen(text) + 1);
            memset(data, 0, strlen(text) + 1);
            if(!data){
                LOG(ERROR) << "malloc error, msg:[" << strerror(errno) << "]";
                return "";
            }

            datacloak::Utils::b2s(text, data);
            std::string ret_s(data);
            free(data);
            driver_Free(&text);
            LOG(INFO) << "driverE4_SM2PrivateKeyDecrypt:\n" << "original_msg[" << msg << "]\ndecrypt_data[" << ret_s << "]";
            return ret_s;
        }

    }

    int Crypto::GenerateKeypair(int nid ,char *key_index, char *engin_name) {
        int err = 0;
        ENGINE *engine = nullptr;
        EVP_PKEY *pkey = nullptr;
        EVP_PKEY_CTX *pkey_ctx = nullptr;
        bool engin_init_flag = false;
        do{
            if(!engin_name){
                LOG(ERROR) << "please set a correct engine name";
                err = -1;
                break;
            }
            if(!key_index){
                LOG(ERROR) << "Should set key_index to a correct value";
                err = -1;
                break;
            }
            engine = ENGINE_by_id(engin_name);
            if(!engine){
                LOG(ERROR) << "ENGINE_by_id error,";
                ERR_print_errors_fp(stderr);
                err = -1;
                break;
            }
            err = ENGINE_init(engine);
            if(err != 1){
                LOG(ERROR) << "ENGINE_init error";
                ERR_print_errors_fp(stderr);
                err = -1;
                break;
            }
            engin_init_flag = true;
            err = EVP_PKEY_CTX_ctrl(pkey_ctx, -1,
                                    EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
                                    EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
                                    NID_sm2, nullptr);
            if(err != 1){
                LOG(ERROR) << "EVP_PKEY_CTX_ctrl error";
                ERR_print_errors_fp(stderr);
                err = -1;
                break;
            }

            err = EVP_PKEY_CTX_ctrl(pkey_ctx, -1,
                              EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
                              EVP_PKEY_CTRL_EC_PARAM_ENC,
                              OPENSSL_EC_NAMED_CURVE, nullptr);
            if(err != 1){
                LOG(ERROR) << "EVP_PKEY_CTX_ctrl error";
                ERR_print_errors_fp(stderr);
                err = -1;
                break;
            }
            EVP_PKEY_CTX_set_app_data(pkey_ctx, (void *) key_index);

            err = EVP_PKEY_keygen(pkey_ctx, &pkey);

            if(err != 1){
                LOG(ERROR) << "EVP_PKEY_keygen error";
                ERR_print_errors_fp(stderr);
                err = -1;
                break;
            }else{
                err = 0;
            }
        } while (false);
        if(engine){
            if(engin_init_flag){
                ENGINE_finish(engine);
            }
            ENGINE_free(engine);
        }
        return err;
    }

    void Crypto::TestCA() {
        int err = GenerateKeypair(NID_sm2,
                        CA_KEY,
                        ENGINE_NAME);
        if(err != 0){
            return;
        }
        X509_REQ *req = nullptr;
        err = GenerateCSR(CA_KEY, NID_sm3, ENGINE_NAME, "DATACLOAK", (void**)&req);
        if(err != 0){
            return;
        }


    }

    void Crypto::GlobalInit() {
        ENGINE_load_builtin_engines();
    }

    int Crypto::GenerateCSR(char *key_index, int hash_id, char *engine_name, const char *cname, void** ppreq) {
        int err = 0;
        EVP_PKEY *pkey = nullptr;
        X509_NAME* x509_name = nullptr;
        ENGINE* engine = nullptr;
        X509_REQ** req = (X509_REQ**)ppreq;
        bool engin_init_flag = false;
        do {
            if (!engine_name) {
                LOG(ERROR) << "please set a correct engine name";
                err = -1;
                break;
            }
            if (!key_index) {
                LOG(ERROR) << "Should set key_index to a correct value";
                err = -1;
                break;
            }

            engine = ENGINE_by_id(engine_name);
            BREAK_ERRNO(err, "ENGINE_by_id" );
            err = ENGINE_init(engine);
            BREAK_ERRNO(err, "ENGINE_init");
            engin_init_flag = true;
            *req = X509_REQ_new();
            BREAK_NULL(*req, "X509_REQ_new");
            err = X509_REQ_set_version(*req, 0L);
            BREAK_ERRNO(err, "X509_REQ_set_version");

            x509_name = X509_NAME_new();
            BREAK_NULL(x509_name, "X509_NAME_new");
            X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("CN"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Guangdong"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Shenzhen"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("DataCloak"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("AUTH"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(cname), -1, -1, 0);

            err = X509_REQ_set_subject_name(*req, x509_name);
            BREAK_ERRNO(err, "X509_REQ_set_subject_name");

            pkey = ENGINE_load_private_key(engine, key_index, nullptr, nullptr);
            BREAK_NULL(pkey, "ENGINE_load_private_key");

            err = X509_REQ_set_pubkey(*req, pkey);
            BREAK_NULL(pkey, "X509_REQ_set_pubkey");

            err = X509_REQ_sign(*req, pkey, EVP_get_digestbynid(hash_id));
            if( err <= 0){
                ERR_print_errors_fp(stderr);
                LOG(ERROR) << "X509_REQ_sign error";
                err = -1;
                break;
            }
            err = 0;
        } while (false);

        if(x509_name){
            X509_NAME_free(x509_name);
        }
        if(pkey){
            EVP_PKEY_free(pkey);
        }
        if(engine){
            if(engin_init_flag){
                ENGINE_finish(engine);
            }
            ENGINE_free(engine);
        }
        return err;
    }

    int
    Crypto::SignCrt(void *crt_req, char *key_index, char *crt_file, int hash_id, char *engine_name, int days) {
        int err = 0;ENGINE* engine = nullptr;
        X509_REQ* req = (X509_REQ*)crt_req;
        bool engin_init_flag = false;
        X509 *x509 = nullptr;
        EVP_PKEY* pkey = nullptr;
        BIO* bio = nullptr;
        do {
            if (!engine_name) {
                LOG(ERROR) << "please set a correct engine name";
                err = -1;
                break;
            }
            if (!key_index) {
                LOG(ERROR) << "Should set key_index to a correct value";
                err = -1;
                break;
            }

            engine = ENGINE_by_id(engine_name);
            BREAK_ERRNO(err, "ENGINE_by_id" );
            err = ENGINE_init(engine);
            BREAK_ERRNO(err, "ENGINE_init");
            engin_init_flag = true;

            x509 = X509_new();
            BREAK_NULL(x509, "X509_new");

            err = X509_set_issuer_name(x509, X509_REQ_get_subject_name(req));
            BREAK_ERRNO(err, "X509_set_issuer_name");

            err = X509_set_subject_name(x509, X509_REQ_get_subject_name(req));
            BREAK_ERRNO(err, "X509_set_subject_name");
            if(!X509_time_adj_ex(X509_getm_notAfter(x509), days, 0, NULL) ){
                ERR_print_errors_fp(stderr);
                err = -1;
                break;
            }
            err = X509_set_pubkey(x509, X509_REQ_get0_pubkey(req));
            BREAK_ERRNO(err, "X509_set_pubkey");

            pkey = ENGINE_load_private_key(engine, key_index, NULL, NULL);
            err = X509_sign(x509, pkey, EVP_get_digestbynid(hash_id));
            if(err <= 0){
                ERR_print_errors_fp(stderr);
                err = -1;
                break;
            }
            bio = BIO_new_file(crt_file, "w+");
            BREAK_NULL(bio, "BIO_new_file");
            err = PEM_write_bio_X509(bio, x509);
            BREAK_ERRNO(err, "PEM_write_bio_X509");
            err = 0;
        } while (false);

        if(bio){
            BIO_free(bio);
        }
        if(pkey){
            EVP_PKEY_free(pkey);
        }
        if(x509){
            X509_free(x509);
        }
        if(engine){
            if(engin_init_flag){
                ENGINE_finish(engine);
            }
            ENGINE_free(engine);
        }
        return err;
    }

    std::string Crypto::GenerateRandomNumber(const std::string &length) {
        char *random = nullptr;
        char *len = (char*)length.c_str();
        int err = driverCR_GenerateRandomNumber(len, &random);
        if(err != 0){
            LOG(ERROR) << "driverCR_GenerateRandomNumber error, error[" << err << "]";
            return "";
        }
        LOG(INFO) << "random number[" << random << "]";
        return std::string{random};
    }

}
