cmake_minimum_required(VERSION 3.21)
project(crypto_manager)

set(CMAKE_CXX_STANDARD 11)
set(thirdparty "${CMAKE_SOURCE_DIR}/../thirdparty")
include_directories(${CMAKE_SOURCE_DIR}/src)
find_package(Threads REQUIRED)

set(CMAKE_CXX_FLAGS "-g")
set(SSL_TYPE "tassl")
#add_definitions(-D__cplusplus)

set(SSL_TYPE "openssl" CACHE STRING "ssl type (tassl/openssl)")

if(${SSL_TYPE} MATCHES "tassl")
    set(gRPC_DIR "${thirdparty}/grpc-with-tassl/lib/cmake/grpc")
    set(Protobuf_DIR "${thirdparty}/grpc-with-tassl/lib64/cmake/protobuf")
    set(OPENSSL_CRYPTO_LIBRARY "${thirdparty}/tassl/lib/libcrypto.a")
    set(OPENSSL_INCLUDE_DIR "${thirdparty}/tassl/include")
    set(OPENSSL_SSL_LIBRARY "${thirdparty}/tassl/lib/libssl.a")
else()
    set(gRPC_DIR "${thirdparty}/grpc-with-openssl-1.1.1l/lib/cmake/grpc")
    set(Protobuf_DIR "${thirdparty}/grpc-with-openssl-1.1.1l/lib64/cmake/protobuf")
    set(OPENSSL_CRYPTO_LIBRARY "${thirdparty}/openssl-1.1.1l/lib/libcrypto.a")
    set(OPENSSL_INCLUDE_DIR "${thirdparty}/openssl-1.1.1l/include")
    set(OPENSSL_SSL_LIBRARY "${thirdparty}/openssl-1.1.1l/lib/libssl.a")
endif()


find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${Protobuf_VERSION}")
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(gflags_DIR "${thirdparty}/gflags-2.2.2/lib/cmake/gflags")
find_package(gflags CONFIG REQUIRED)
message(STATUS "Using gflags ${gflags_VERSION}")

set(glog_DIR "${thirdparty}/glog-0.5.0/lib64/cmake/glog")
find_package(glog CONFIG REQUIRED)


set(_GLOG_LIBGLOG glog::glog)
set(_GFLAGS_LIBGFLAGS gflags::libgflags)
set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
set(_PROTOBUF_PROTOC protobuf::protoc)
set(_GRPC_GRPCPP gRPC::grpc++)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)

get_filename_component(key_manager_proto "protos/key_manager.proto" ABSOLUTE)
get_filename_component(key_manager_proto_path "${key_manager_proto}" PATH)

set(key_manager_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/key_manager.pb.cc")
set(key_manager_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/key_manager.pb.h")
set(key_manager_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/key_manager.grpc.pb.cc" )
set(key_manager_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/key_manager.grpc.pb.h")

add_custom_command(
        OUTPUT "${key_manager_proto_srcs}" "${key_manager_proto_hdrs}" "${key_manager_grpc_srcs}" "${key_manager_grpc_hdrs}"
        COMMAND ${_PROTOBUF_PROTOC}
        ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${key_manager_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${key_manager_proto}"
        DEPENDS "${key_manager_proto}"
)

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

include_directories(${thirdparty}/grpc/include)
include_directories(${thirdparty}/glog-0.5.0/include)
include_directories(${thirdparty}/tassl/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/crypto)
include_directories(${thirdparty}/libTassAPI4EHVSM/include)

link_directories(${thirdparty}/libTassAPI4EHVSM/lib)
link_directories(${thirdparty}/tassl/lib)
add_executable(key_manager
        ${key_manager_proto_srcs}
        ${key_manager_grpc_srcs}
        src/server.cpp
        src/server.h
        src/main.cpp src/utils.cpp src/utils.h src/crypto/crypto.cpp src/crypto/crypto.h src/log.cpp src/log.h)


target_link_libraries(key_manager
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF}
        ${_GLOG_LIBGLOG}
        pthread
        TassAPI4EHVSM
        )