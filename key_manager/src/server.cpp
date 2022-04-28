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
        LOG(INFO) << __FUNCTION__ ;
        HashRequest request;
        std::string digest = "";
        while (reader->Read(&request)){
            datacloak::server::CryptoAlgType type = request.type();
            switch (type) {
                case server::SM3:
                    digest = Crypto::sm3_hash(request.msg());
                    if(digest.empty()){
                        response->set_error_code(server::DC_KEY_MANAGER_SM3_HASH_FAILED);
                        response->set_error_message("sm3 digest failed");
                    }else{
                        response->set_error_code(server::DC_OK);
                        response->set_error_message("succeed");
                    }
                    break;
                default:
                    response->set_error_code(server::DC_KEY_MANAGER_SM3_HASH_UNKNOWN_TYPE);
                    response->set_error_message("Unknown hash type");
                    break;
            }
        }
        response->set_msg(digest);
        LOG(INFO) << __FUNCTION__ << "exit";
        return Status::OK;
    }

    Status KeyManagerServer::Sm2VerifyWithSm3(ServerContext *context, const Sm2VerifyWithSm3Request *request,
                                              Sm2VerifyWithSm3Response *response) {
        LOG(INFO) << __FUNCTION__ ;
        bool ret = Crypto::SM2_verify_with_sm3(request->pri_key(), request->sig(), request->msg());
        if(ret){
            response->set_error_code(server::DC_OK);
            response->set_error_message("success");
        }else{
            response->set_error_code(server::DC_KEY_MANAGER_SM3_VERIFY_MSG_SIGN_FAILED);
            response->set_error_message("verify failed");
        }
        LOG(INFO) << __FUNCTION__ << "exit";
        return Status::OK;
    }
    Status KeyManagerServer::Sm2SignWithSm3(ServerContext *context, const Sm2SignWithSm3Request *request,
                                            Sm2SignWithSm3Response *response) {
        LOG(INFO) << __FUNCTION__ ;
        std::string private_key = request->pri_key();
        std::string msg = request->msg();
        std::cout << "private_key:\n" << private_key << std::endl;
        std::cout << "msg:" << msg << std::endl;
        std::string msg_hash = Crypto::sm3_hash(msg);

        if(msg_hash.empty()){
            LOG(ERROR) << "get hash failed";
            response->set_error_message("sm3 digest failed");
            response->set_error_code(server::DC_KEY_MANAGER_SM3_HASH_FAILED);
            return Status::OK;
        }

        //std::string sign = Crypto::SM2_sign(request->pri_key().c_str(), request->msg());
        std::string sign = Crypto::SM2_sign_with_sm3(request->msg());
        response->set_error_code(server::DC_OK);
        response->set_msg(sign);
        LOG(INFO) << __FUNCTION__ << "exit";
        return Status::OK;
    }

    Status KeyManagerServer::IssueGmCert(ServerContext *context, const IssueGmCertRequest *request,
                                         IssueGmCertResponse *response) {
        LOG(INFO) << __FUNCTION__ ;
        LOG(INFO) << "\n" << "client pub key:\n" << request->client_pub_pem() << "\ncname[" << request->cname() <<"]";
        std::string client_cert = Crypto::IssueGmCert(request->client_pub_pem(), request->cname());
        if(!client_cert.empty()){
            response->set_error_code(server::DC_OK);
            response->set_error_message("succeed");
            response->set_cert_pem(client_cert);
        }else{
            response->set_error_code(server::DC_KEY_MANAGER_SM3_GENERATE_CERT_ERROR);
            response->set_error_message("Generate client cert failed");
            response->set_cert_pem(client_cert);
        }
        LOG(INFO) << __FUNCTION__ << "exit";
        return Status::OK;

    }

    Status KeyManagerServer::AsymEncrypt(ServerContext *context, const AsymEncryptRequest *request,
                                            AsymEncryptResponse *response) {
        std::string pub_key = request->pub_key();
        std::string msg = request->msg();
        datacloak::server::CryptoAlgType type = request->type();
        LOG(INFO) << "pub_key:" << pub_key;
        LOG(INFO) << "msg:" << msg;
        std::string cipher;
        switch (type)
        {
        case datacloak::server::CryptoAlgType::SM2:
            cipher = Crypto::SM2_Encrypt(msg, pub_key);
            if (cipher == "") {
                response->set_error_code(server::DC_CRYPTO_FAILED);
            }
            else {
                std::cout << "cipher: " << cipher << std::endl;
                response->set_error_code(server::DC_OK);
                response->set_msg(cipher);
            }
            break;

        default:
            response->set_error_code(server::DC_CRYPTO_ALG_INVALID);
            break;
        }

        return Status::OK;
    }


    Status KeyManagerServer::AsymDecrypt(ServerContext *context, const AsymDecryptRequest *request,
                                            AsymDecryptResponse *response) {
        std::string pri_key = request->pri_key();
        std::string msg = request->msg();
        datacloak::server::CryptoAlgType type = request->type();
        LOG(INFO) << "pri_key:" << pri_key;
        LOG(INFO) << "msg:" << msg;
        std::string text;
        switch (type)
        {
        case datacloak::server::CryptoAlgType::SM2:
            text = Crypto::SM2_Decrypt(msg, pri_key);
            if (text == "") {
                response->set_error_code(server::DC_CRYPTO_FAILED);
            }
            else {
                response->set_error_code(server::DC_OK);
                response->set_msg(text);
            }
            break;

        default:
            response->set_error_code(server::DC_CRYPTO_ALG_INVALID);
            break;
        }
        return Status::OK;
    }
}




