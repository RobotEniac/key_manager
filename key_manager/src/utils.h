//
// Created by edward on 4/24/22.
//

#ifndef CRYPTO_MANAGER_UTILS_H
#define CRYPTO_MANAGER_UTILS_H

#include <iostream>
#include <fstream>

namespace datacloak{
    class Utils {
    public:
        static std::string ReadFile(const std::string& path);
        static int b2s(const char *bin, char *out);
        static bool APIInit();
    };
}



#endif //CRYPTO_MANAGER_UTILS_H
