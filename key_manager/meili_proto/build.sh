#!/bin/sh
protoc --go_opt=paths=source_relative --go_out=plugins=grpc:../ --proto_path=../ meili_proto/datacloak/server/key_manager.proto -I ../meili_proto/
if [ $? != 0 ];
then
    protoc --go-grpc_opt=paths=source_relative --go-grpc_out=../ --proto_path=../ meili_proto/datacloak/server/key_manager.proto -I ../meili_proto
fi
