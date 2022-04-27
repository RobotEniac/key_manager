//
// Created by edward on 4/25/22.
//

#ifndef CRYPTO_MANAGER_LOG_H
#define CRYPTO_MANAGER_LOG_H
#include <glog/logging.h>
namespace datacloak{
    class Log {
    public:
        static void LogInit(std::string &value);
    };
}



#endif //CRYPTO_MANAGER_LOG_H
