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
        int err = driverE7_GenerateSM2KeyPair((char*)index.c_str(), (char*)tag.c_str(),
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

    bool Crypto::SM2_verify_with_sm3(const std::string &index, const std::string &sign, const std::string &msg) {
        std::string hash = sm3_hash(msg);
        int err = driverEF_SM2PublicKeyVerifyWithDataDigest(
                "0",
                (char*)sign.c_str(),
                (char*)hash.c_str(),
                (char*)index.c_str()
        );
        if(err != 0){
            LOG(ERROR) << "driverEF_SM2PublicKeyVerifyWithDataDigest failed, errno[" << err << "]";
            LOG(INFO) << "key_index[" << index <<"],sign["<<sign <<"],msg[" << msg <<"]";
            return false;
        }
        LOG(INFO) << "driverEF_SM2PublicKeyVerifyWithDataDigest succeed";
        return true;
    }

    std::string Crypto::SM2_sign_with_sm3(const std::string &data,const std::string &key_index) {
        int err = 0;
#if 0
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
#endif
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
		err = driverED_SM2PrivateKeySignWithDataDigest(
					(char*)hash.c_str(),
                    (char*)key_index.c_str(),
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
				(char*)key_index.c_str()
				);
		if(err != 0){
			LOG(ERROR) << "driverEF_SM2PublicKeyVerifyWithDataDigest failed, errno[" << err << "]";
			return "";
		}
		LOG(INFO) << "driverEF_SM2PublicKeyVerifyWithDataDigest succeed";
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
    std::string Crypto::IssueGmCert(const std::string &pub, const std::string &name) {

        X509 *x509 = nullptr;
        EVP_PKEY *pk_ca = nullptr;
        EC_KEY *ec_key = nullptr;
        X509_NAME *x509_name = nullptr;
        std::string cert_str = "";
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
            BIO *ca_key_bio = BIO_new_mem_buf(ca_private_key.c_str(), -1);
            EC_KEY *ec_ca_key = PEM_read_bio_ECPrivateKey(ca_key_bio,  NULL, password, NULL);
            if(!ec_ca_key){
                LOG(ERROR) << "read ca key failed";
                break;
            }

#if 0
            ec_key = EC_KEY_new_by_curve_name(NID_sm2);
            if(!ec_key){
                std::cout << "EC_KEY_new failed";
                break;
            }
            int ret = EC_KEY_generate_key(ec_key);
            if(ret == 0){
                std::cout << "EC_KEY_generate_key failed";
                break;
            }
#endif
            int err = EVP_PKEY_assign_EC_KEY(pk_ca, ec_ca_key);
            if(err == 0){
                std::cout << "EVP_PKEY_assign_EC_KEY error";
                break;
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
#if 1
            X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("CN"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Guangdong"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Shenzhen"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("DataCloak"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("AUTH"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(name.c_str()), -1, -1, 0);
#endif
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
        return cert_str;

#if 0
        X509 *x509 = nullptr;
        EVP_PKEY *pk = nullptr;
        EC_KEY *ec_key = nullptr;

        std::string cert_str = "";
        X509_NAME *x509_name = nullptr;
        BIO* root_private_key_bio = nullptr;
        EC_KEY* root_private_key = nullptr;
        BIO* client_pub_bio = nullptr;
        EC_KEY* client_pub_key = nullptr;
        BIO* ca_cert_bio = nullptr;
        X509* root_certificate = nullptr;
        X509_NAME* issuer_name = nullptr;
        do{
#if 1
            pk = EVP_PKEY_new();
            if(pk == nullptr){
                LOG(ERROR) << "EVP_PKEY_new error";
                break;
            }

            x509 = X509_new();
            if(x509 == nullptr){
                LOG(ERROR) << "X509_new error";
                break;
            }
            ec_key = EC_KEY_new_by_curve_name(NID_sm2);
            if(!ec_key){
                LOG(ERROR) << "EC_KEY_new failed";
                break;
            }
            int ret = EC_KEY_generate_key(ec_key);
            if(ret == 0){
                LOG(ERROR) << "EC_KEY_generate_key failed";
                break;
            }

            int err = EVP_PKEY_assign_EC_KEY(pk, ec_key);
            if(err == 0){
                LOG(ERROR) << "EVP_PKEY_assign_EC_KEY error";
                break;
            }
#endif
            x509 = X509_new();
            if(x509 == nullptr){
                LOG(ERROR) << "X509_new error";
                break;
            }
            std::cout << "====private key start====\n";
            std::cout << ca_private_key << "\n";
            std::cout << "====private key end====\n";
            root_private_key_bio = BIO_new_mem_buf(ca_private_key.c_str(), -1);
            root_private_key = PEM_read_bio_ECPrivateKey(root_private_key_bio, NULL, NULL, NULL);
            if(!root_private_key){
                LOG(ERROR) << "read ca key failed";
                break;
            }
            EVP_PKEY *pprivate_key = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(pprivate_key, root_private_key);

            client_pub_bio = BIO_new_mem_buf(pub.c_str(), -1);
            client_pub_key = PEM_read_bio_EC_PUBKEY(client_pub_bio, NULL, NULL, NULL);
            if(!client_pub_key){
                LOG(ERROR) << "read client pub key failed";
                break;
            }
            EVP_PKEY *_pub_key = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(_pub_key, client_pub_key);
            ca_cert_bio = BIO_new_mem_buf(ca_cert.c_str(), -1);
            root_certificate = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
            if(!root_certificate){
                LOG(ERROR) << "root certificate read error";
                break;
            }
            issuer_name = X509_get_subject_name(root_certificate);
            X509_set_version(x509, 2);
            ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
            X509_gmtime_adj(X509_get_notBefore(root_certificate), 0);
            X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 365);
            X509_set_pubkey(x509, pk);
#if 0
            x509_name = X509_get_subject_name(x509);

            X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("CN"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Guangdong"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Shenzhen"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("DataCloak"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("AUTH"), -1, -1, 0);
            X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(name.c_str()), -1, -1, 0);
#endif

            add_ext(x509, NID_basic_constraints, const_cast<char *>("critical,CA:FALSE"));
            add_ext(x509, NID_ext_key_usage, const_cast<char *>("TLS Web Client Authentication,TLS Web Server Authentication "));
            add_ext(x509, NID_key_usage, const_cast<char *>("critical,Digital Signature,Certificate Sign,CRL Sign "));
            std::string alt_name = std::string{"DNS:"} + name + ",email:admin@datacloak.com";
            add_ext(x509, NID_subject_alt_name, const_cast<char *>(alt_name.c_str()));

            X509_set_issuer_name(x509, issuer_name);
            err = X509_sign(x509, pk, EVP_sm3());
            if(err == 0){
                LOG(ERROR) << "X509_sign error, errno[" << ERR_get_error()  << "], error msg[" <<
                ERR_error_string(ERR_get_error(), NULL) << "]";

                break;
            }
            PEM_write_X509(stderr, x509);
            BIO* client_cert_bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(client_cert_bio, x509);
            char cert_buf[102400] = {0};
            int len = BIO_read(client_cert_bio, cert_buf, 102400);
            cert_str.assign(cert_buf, cert_buf + len);
        } while (false);
        /*
        X509_NAME *x509_name = nullptr;
        BIO* root_private_key_bio = nullptr;
        EVP_PKEY* root_private_key = nullptr;
        BIO* client_pub_bio = nullptr;
        EVP_PKEY* client_pub_key = nullptr;
        BIO* ca_cert_bio = nullptr;
        X509* root_certificate = nullptr;
        X509_NAME* issuer_name = nullptr;
         */
        if(root_private_key){
            EC_KEY_free(root_private_key);
        }
        if(root_private_key_bio){
            BIO_free(root_private_key_bio);
        }
        if(client_pub_key){
            EC_KEY_free(client_pub_key);
        }
        if(client_pub_bio){
            BIO_free(client_pub_bio);
        }
        return cert_str;
#endif

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
            return ret_s;
        }

    }
}
