//
// Created by edward on 4/24/22.
//

#include <server.h>
#include <utils.h>
#include <openssl/sm3.h>
#include <openssl/evp.h>
#include <crypto.h>
#include "log.h"

namespace datacloak{
    void KeyManagerServer::RunServer(const std::string &ca_cert_path, const std::string &server_key_path,
                                        const std::string &server_cert_path,const std::string& listen_addr, bool use_tls) {
        std::string root_cert = "";
        std::string server_cert = "";
        std::string server_key = "";
        if(use_tls){
            root_cert = Utils::ReadFile(ca_cert_path);
            server_cert = Utils::ReadFile(server_cert_path);
            server_key = Utils::ReadFile(server_key_path);
            if((root_cert == "" || server_cert == "" || server_key == "") ){
                return;
            }
        }
        if(listen_addr == ""){
            fprintf(stderr, "Need to set a listen address\n");
            return;
        }

        KeyManagerServer service;
        ServerBuilder builder;
        if(use_tls){
            grpc::SslServerCredentialsOptions options;
            options.pem_root_certs = root_cert;
            options.pem_key_cert_pairs.push_back({server_key, server_cert});

            std::shared_ptr<grpc::ServerCredentials> credentials = grpc::SslServerCredentials(options);
            builder.AddListeningPort(listen_addr, credentials);
        }else{
            builder.AddListeningPort(listen_addr, grpc::InsecureServerCredentials());
        }


        builder.RegisterService(&service);

        std::unique_ptr<Server> server{builder.BuildAndStart()};

        std::cout << "Listening on " << listen_addr << "\n Crypto manager server started...\n";

        server->Wait();

    }

    Status
    KeyManagerServer::Hash(ServerContext *context, grpc::ServerReader<HashRequest> *reader, HashResponse *response) {
        HashRequest request;
        while (reader->Read(&request)){
            datacloak::server::key_manager::CryptoAlgType type = request.type();
            std::string digest = "";
            switch (type) {
                case server::key_manager::SM3:
                    digest = Crypto::sm3_hash(request.msg());
                    if(digest.empty()){
                        response->set_error_code(server::key_manager::DC_KEY_MANAGER_SM3_HASH_FAILED);
                        response->set_error_message("sm3 digest failed");
                    }else{
                        response->set_error_code(server::key_manager::DC_OK);
                        response->set_error_message("succeed");
                    }
                    break;
                default:
                    response->set_error_code(server::key_manager::DC_KEY_MANAGER_SM3_HASH_UNKNOWN_TYPE);
                    response->set_error_message("Unknown hash type");
            }
            response->set_msg(digest);
        }
        return Status::OK;
    }

    Status KeyManagerServer::Sm2SignWithSm3(ServerContext *context, const Sm2SignWithSm3Request *request,
                                            Sm2SignWithSm3Response *response) {
        std::string private_key = request->pri_key();
        std::string msg = request->msg();
        std::cout << "private_key:\n" << private_key << std::endl;
        std::cout << "msg:" << msg << std::endl;
        std::string msg_hash = Crypto::sm3_hash(msg);

        if(msg_hash.empty()){
            LOG(ERROR) << "get hash failed";
            response->set_error_message("sm3 digest failed");
            response->set_error_code(server::key_manager::DC_KEY_MANAGER_SM3_HASH_FAILED);
            return Status::OK;
        }

        //std::string sign = Crypto::SM2_sign(request->pri_key().c_str(), request->msg());
        std::string sign = Crypto::SM2_sign_with_sm3(request->msg());
        response->set_error_code(server::key_manager::DC_OK);
        response->set_msg(sign);
        return Status::OK;
    }

    Status KeyManagerServer::IssueGmCert(ServerContext *context, const IssueGmCertRequest *request,
                                         IssueGmCertResponse *response) {
        return Status::OK;

    }

    Status KeyManagerServer::AsymEncrypt(ServerContext *context, const AsymEncryptRequest *request,
                                            AsymEncryptResponse *response) {
        std::string pub_key = request->pub_key();
        std::string msg = request->msg();
        datacloak::server::key_manager::CryptoAlgType type = request->type();
        std::cout << "pub_key:" << pub_key << std::endl;
        std::cout << "msg:" << msg << std::endl;
        std::string cipher;
        switch (type)
        {
        case datacloak::server::key_manager::CryptoAlgType::SM2:
            cipher = Crypto::SM2_Encrypt(msg, pub_key);
            if (cipher == "") {
                response->set_error_code(server::key_manager::DC_CRYPTO_FAILED);
            }
            else {
                response->set_error_code(server::key_manager::DC_OK);
                response->set_msg(cipher);
            }
            break;
        
        default:
            response->set_error_code(server::key_manager::DC_CRYPTO_ALG_INVALID);
            break;
        }

        return Status::OK;
    }


    Status KeyManagerServer::AsymDecrypt(ServerContext *context, const AsymDecryptRequest *request,
                                            AsymDecryptResponse *response) {
        std::string pri_key = request->pri_key();
        std::string msg = request->msg();
        datacloak::server::key_manager::CryptoAlgType type = request->type();
        std::cout << "pri_key:" << pri_key << std::endl;
        std::cout << "msg:" << msg << std::endl;
        std::string text;
        switch (type)
        {
        case datacloak::server::key_manager::CryptoAlgType::SM2:
            text = Crypto::SM2_Decrypt(msg, pri_key);
            if (text == "") {
                response->set_error_code(server::key_manager::DC_CRYPTO_FAILED);
            }
            else {
                response->set_error_code(server::key_manager::DC_OK);
                response->set_msg(text);
            }
            break;
        
        default:
            response->set_error_code(server::key_manager::DC_CRYPTO_ALG_INVALID);
            break;
        }

        return Status::OK;
    }
}




