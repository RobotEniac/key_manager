//
// Created by edward on 4/25/22.
//

#include <log.h>

namespace datacloak{
    void Log::LogInit(std::string &value) {
        google::InitGoogleLogging(value.c_str());
        FLAGS_alsologtostderr = true;
        FLAGS_colorlogtostderr = true;
        FLAGS_max_log_size = 10;
        FLAGS_stop_logging_if_full_disk = true;
    }
}
