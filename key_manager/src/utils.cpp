//
// Created by edward on 4/24/22.
//

#include <utils.h>
#include <cerrno>
#include <cstring>
#include <TassAPI4EHVSM.h>
#include <log.h>
namespace datacloak{
    std::string Utils::ReadFile(const std::string &path) {
        std::ifstream file(path);
        std::string content = "";
        if(file.is_open()){
            content.assign((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
            file.close();
            return content;
        }else{
            fprintf(stderr, "read %s error:%s\n", path.c_str(), strerror(errno));
        }
        return content;
    }

    int Utils::b2s(const char *bin, char *out) {
        int i = 0;
        char buf[4] = {0};
        int ret = 0;
        const char *ptr = bin;
        for(i = 0; i < strlen(bin) / 2; i++){
            memset(buf, 0, sizeof(buf));
            memcpy(buf, ptr, 2);
            ptr += 2;
            ret = strtol(buf, NULL, 16);
            memset(out++, ret, 1);
        }
        return i;
    }

    bool Utils::APIInit() {
        char cfg[] ="{"           \
        "[Logger]\n"              \
        "level=1\n"               \
        "path=./tass.log\n"	      \
        "maxSize=1\n"             \
        "backupNum=6\n"           \
        "[Global]\n"              \
        "mechanism=1\n"           \
        "[Host 1]\n"              \
        "model=SJJ1310\n"         \
        "ip=10.10.3.21\n"         \
        "port=8018\n"             \
        "timeout=5\n"             \
        "minConn=10\n"             \
        "maxConn=10\n"            \
        "protocol=1\n"            \
        "}";
        int err = driver_Initialize(cfg);
        if(err){
            LOG(ERROR) << "driver_Initialize error[" << err <<"]";
            return false;
        }else{
            LOG(INFO) << "driver_Initialize succeed";
        }
        return true;
    }
}
