//
// Created by edward on 4/25/22.
//

#ifndef CRYPTO_MANAGER_CRYPTO_H
#define CRYPTO_MANAGER_CRYPTO_H
#include <string>
#include <map>

#define ENGINE_NAME     "tasshsm_sm2"

namespace datacloak{
    class Crypto {
    public:
        static std::string sm3_hash(const std::string& msg);
        static std::string SM2_sign(const std::string& key, const std::string& hash);
        static std::string SM2_sign(const char* key_index, const std::string& data);
        static void GenerateECCKey();
        static std::string ECDSA_SIG_to_string(const void *sig);
        static std::string SM2_sign_with_sm3(const std::string &data);
        static std::string IssueGmCert(const std::string& pub, const std::string& name);
        static void SetRootKeys(const std::string& root_cert, const std::string& root_private_key);
    private:
        static std::map<std::string, std::string> key_map_;
        static std::string ca_cert;
        static std::string ca_private_key;
    private:
        static int add_ext(void *cert, int nid, char *value);
    };
}



#endif //CRYPTO_MANAGER_CRYPTO_H
