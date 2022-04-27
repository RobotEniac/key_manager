//
// Created by edward on 4/24/22.
//

#ifndef CRYPTO_MANAGER_SERVER_H
#define CRYPTO_MANAGER_SERVER_H

#include <key_manager.grpc.pb.h>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <string>
#include <memory>
using datacloak::server::HashRequest;
using datacloak::server::HashResponse;

using datacloak::server::AsymEncryptRequest;
using datacloak::server::AsymEncryptResponse;
using datacloak::server::AsymDecryptRequest;
using datacloak::server::AsymDecryptResponse;

//Sm2SignWithSm3

using datacloak::server::Sm2SignWithSm3Request;
using datacloak::server::Sm2SignWithSm3Response;

//issue cert
using datacloak::server::IssueGmCertRequest;
using datacloak::server::IssueGmCertResponse;

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
namespace datacloak{
class KeyManagerServer final : public datacloak::server::KeyManager::Service{
        Status Hash(ServerContext* context, grpc::ServerReader<HashRequest>* reader, HashResponse* response)override;
        Status AsymEncrypt(ServerContext* context, const AsymEncryptRequest* request,
                           AsymEncryptResponse* response)override;
        Status AsymDecrypt(ServerContext *context, const AsymDecryptRequest *request,
                           AsymDecryptResponse *response)override;
        Status Sm2SignWithSm3(ServerContext* context, const Sm2SignWithSm3Request* request, Sm2SignWithSm3Response* response)override;

        Status IssueGmCert(ServerContext* context, const IssueGmCertRequest* request, IssueGmCertResponse* response)override;

public:
    static void RunServer(const std::string& ca_cert_path,
                     const std::string& server_key_path,
                     const std::string& server_cert_path,
                     const std::string& listen_addr, bool use_tls);
    };
}




#endif //CRYPTO_MANAGER_SERVER_H
