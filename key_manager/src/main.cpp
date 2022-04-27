#include <iostream>
#include <server.h>
#include <string>
#include <cxxopts.hpp>
#include <log.h>
#include <crypto.h>
#include <utils.h>
int main(int argc, char *argv[]) {
    std::string process_name = std::string{argv[0]};
    datacloak::Log::LogInit(process_name);

    datacloak::Crypto::GenerateECCKey();
    if(!datacloak::Utils::APIInit()){
        return -1;
    }
    cxxopts::Options options("crypto_manager", "Manage all crypto things");

    options.add_options()
            ("r,root","set root cert file path", cxxopts::value<std::string>())
            ("k,key","set server private key file path", cxxopts::value<std::string>())
            ("c,cert","set server cert file path", cxxopts::value<std::string>())
            ("l,listen", "set listen addr", cxxopts::value<std::string>())
            ("t,tls", "enable tls or not", cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage")
            ;
    auto result = options.parse(argc, argv);

    if(result.count("help")){
        std::cout << options.help() << std::endl;
        exit(0);
    }
    std::string root_cert_path = "";
    std::string server_cert_path = "";
    std::string server_key_path = "";
    std::string addr = "";
    bool use_tls = false;
    if(result.count("root"))
        root_cert_path = result["root"].as<std::string>();
    if(result.count("cert"))
        server_cert_path = result["cert"].as<std::string>();
    if(result.count("key"))
        server_key_path = result["key"].as<std::string>();
    if(result.count("listen"))
        addr = result["listen"].as<std::string>();
    if(result.count("tls"))
        use_tls = result["tls"].as<bool>();
    datacloak::KeyManagerServer::RunServer(root_cert_path,
                                              server_key_path,
                                              server_cert_path,
                                              addr, use_tls);
    return 0;
}
