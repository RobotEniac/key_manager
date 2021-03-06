#include <iostream>
#include <server.h>
#include <string>
#include <cxxopts.hpp>
#include <log.h>
#include <crypto.h>
#include <utils.h>

void testCA(){
    datacloak::Crypto::TestCA();
}

int main(int argc, char *argv[]) {
    std::string process_name = std::string{argv[0]};
    datacloak::Log::LogInit(process_name);
    datacloak::Crypto::GlobalInit();


    cxxopts::Options options("crypto_manager", "Manage all crypto things");

    options.add_options()
            ("r,root","set root cert file path", cxxopts::value<std::string>())
            ("k,key","set server private key file path", cxxopts::value<std::string>())
            ("c,cert","set server cert file path", cxxopts::value<std::string>())
            ("l,listen", "set listen addr", cxxopts::value<std::string>())
            ("t,tls", "enable tls or not", cxxopts::value<bool>()->default_value("false"))
            ("ca", "root certificate", cxxopts::value<std::string>())
            ("private", "root private key", cxxopts::value<std::string>())
            ("index", "private key index", cxxopts::value<std::string>())
            ("test-ca", "test ca api", cxxopts::value<bool>()->default_value("false"))
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
    std::string ca_cert_path = "";
    std::string ca_private_key_path = "";
    std::string private_key_index = "";
    bool test_ca = false;
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
    if(result.count("ca"))
        ca_cert_path = result["ca"].as<std::string>();
    if(result.count("private"))
        ca_private_key_path = result["private"].as<std::string>();
    if(result.count("index"))
        private_key_index = result["index"].as<std::string>();
    if(private_key_index == ""){
        private_key_index = "55";
    }

    if(result.count("test-ca"))
        test_ca = result["test-ca"].as<bool>();

    if(test_ca){
        testCA();
        return 0;
    }
    if(!datacloak::Utils::APIInit()){
        return -1;
    }



    datacloak::Crypto::GenerateECCKey(private_key_index);
    datacloak::Crypto::GenerateECCKey("58", "for encrypt");
    datacloak::Crypto::SetKeyIndex(private_key_index);
    if(ca_cert_path == "" || ca_private_key_path == ""){
        LOG(ERROR) << "Need to set root ca info";
        return -1;
    }
    std::string root_cert = datacloak::Utils::ReadFile(ca_cert_path);
    std::string ca_key = datacloak::Utils::ReadFile(ca_private_key_path);

    std::cout << "========================root cert=============================\n";
    std::cout << root_cert <<"\n";
    std::cout << "========================root cert=============================\n";
    std::cout << "========================root key=============================\n";
    std::cout << ca_key <<"\n";
    std::cout << "========================root key=============================\n";
    datacloak::Crypto::SetRootKeys(root_cert, ca_key);
    datacloak::KeyManagerServer::RunServer(root_cert_path,
                                              server_key_path,
                                              server_cert_path,
                                              addr, use_tls);
    return 0;
}
