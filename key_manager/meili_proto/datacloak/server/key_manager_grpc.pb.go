// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: meili_proto/datacloak/server/key_manager.proto

package server

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// KeyManagerClient is the client API for KeyManager service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type KeyManagerClient interface {
	// hash sm3
	Hash(ctx context.Context, opts ...grpc.CallOption) (KeyManager_HashClient, error)
	// sm2 encrypt
	AsymEncrypt(ctx context.Context, in *AsymEncryptRequest, opts ...grpc.CallOption) (*AsymEncryptResponse, error)
	AsymDecrypt(ctx context.Context, in *AsymDecryptRequest, opts ...grpc.CallOption) (*AsymDecryptResponse, error)
	Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error)
	Sm2SignWithSm3(ctx context.Context, in *Sm2SignWithSm3Request, opts ...grpc.CallOption) (*Sm2SignWithSm3Response, error)
	Sm2VerifyWithSm3(ctx context.Context, in *Sm2VerifyWithSm3Request, opts ...grpc.CallOption) (*Sm2VerifyWithSm3Response, error)
	IssueGmCert(ctx context.Context, in *IssueGmCertRequest, opts ...grpc.CallOption) (*IssueGmCertResponse, error)
	// below is low priority
	// random
	RandomUint64(ctx context.Context, in *RandomUint64Request, opts ...grpc.CallOption) (*RandomUint64Response, error)
	// symmetric algorithm
	SymEncrypt(ctx context.Context, in *SymEncryptRequest, opts ...grpc.CallOption) (*SymEncryptResponse, error)
	SymDecrypt(ctx context.Context, in *SymDecryptRequest, opts ...grpc.CallOption) (*SymDecryptResponse, error)
}

type keyManagerClient struct {
	cc grpc.ClientConnInterface
}

func NewKeyManagerClient(cc grpc.ClientConnInterface) KeyManagerClient {
	return &keyManagerClient{cc}
}

func (c *keyManagerClient) Hash(ctx context.Context, opts ...grpc.CallOption) (KeyManager_HashClient, error) {
	stream, err := c.cc.NewStream(ctx, &KeyManager_ServiceDesc.Streams[0], "/datacloak.server.KeyManager/Hash", opts...)
	if err != nil {
		return nil, err
	}
	x := &keyManagerHashClient{stream}
	return x, nil
}

type KeyManager_HashClient interface {
	Send(*HashRequest) error
	CloseAndRecv() (*HashResponse, error)
	grpc.ClientStream
}

type keyManagerHashClient struct {
	grpc.ClientStream
}

func (x *keyManagerHashClient) Send(m *HashRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *keyManagerHashClient) CloseAndRecv() (*HashResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(HashResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *keyManagerClient) AsymEncrypt(ctx context.Context, in *AsymEncryptRequest, opts ...grpc.CallOption) (*AsymEncryptResponse, error) {
	out := new(AsymEncryptResponse)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/AsymEncrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) AsymDecrypt(ctx context.Context, in *AsymDecryptRequest, opts ...grpc.CallOption) (*AsymDecryptResponse, error) {
	out := new(AsymDecryptResponse)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/AsymDecrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error) {
	out := new(SignResponse)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/Sign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) Sm2SignWithSm3(ctx context.Context, in *Sm2SignWithSm3Request, opts ...grpc.CallOption) (*Sm2SignWithSm3Response, error) {
	out := new(Sm2SignWithSm3Response)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/Sm2SignWithSm3", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) Sm2VerifyWithSm3(ctx context.Context, in *Sm2VerifyWithSm3Request, opts ...grpc.CallOption) (*Sm2VerifyWithSm3Response, error) {
	out := new(Sm2VerifyWithSm3Response)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/Sm2VerifyWithSm3", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) IssueGmCert(ctx context.Context, in *IssueGmCertRequest, opts ...grpc.CallOption) (*IssueGmCertResponse, error) {
	out := new(IssueGmCertResponse)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/IssueGmCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) RandomUint64(ctx context.Context, in *RandomUint64Request, opts ...grpc.CallOption) (*RandomUint64Response, error) {
	out := new(RandomUint64Response)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/RandomUint64", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) SymEncrypt(ctx context.Context, in *SymEncryptRequest, opts ...grpc.CallOption) (*SymEncryptResponse, error) {
	out := new(SymEncryptResponse)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/SymEncrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) SymDecrypt(ctx context.Context, in *SymDecryptRequest, opts ...grpc.CallOption) (*SymDecryptResponse, error) {
	out := new(SymDecryptResponse)
	err := c.cc.Invoke(ctx, "/datacloak.server.KeyManager/SymDecrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyManagerServer is the server API for KeyManager service.
// All implementations must embed UnimplementedKeyManagerServer
// for forward compatibility
type KeyManagerServer interface {
	// hash sm3
	Hash(KeyManager_HashServer) error
	// sm2 encrypt
	AsymEncrypt(context.Context, *AsymEncryptRequest) (*AsymEncryptResponse, error)
	AsymDecrypt(context.Context, *AsymDecryptRequest) (*AsymDecryptResponse, error)
	Sign(context.Context, *SignRequest) (*SignResponse, error)
	Sm2SignWithSm3(context.Context, *Sm2SignWithSm3Request) (*Sm2SignWithSm3Response, error)
	Sm2VerifyWithSm3(context.Context, *Sm2VerifyWithSm3Request) (*Sm2VerifyWithSm3Response, error)
	IssueGmCert(context.Context, *IssueGmCertRequest) (*IssueGmCertResponse, error)
	// below is low priority
	// random
	RandomUint64(context.Context, *RandomUint64Request) (*RandomUint64Response, error)
	// symmetric algorithm
	SymEncrypt(context.Context, *SymEncryptRequest) (*SymEncryptResponse, error)
	SymDecrypt(context.Context, *SymDecryptRequest) (*SymDecryptResponse, error)
	mustEmbedUnimplementedKeyManagerServer()
}

// UnimplementedKeyManagerServer must be embedded to have forward compatible implementations.
type UnimplementedKeyManagerServer struct {
}

func (UnimplementedKeyManagerServer) Hash(KeyManager_HashServer) error {
	return status.Errorf(codes.Unimplemented, "method Hash not implemented")
}
func (UnimplementedKeyManagerServer) AsymEncrypt(context.Context, *AsymEncryptRequest) (*AsymEncryptResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AsymEncrypt not implemented")
}
func (UnimplementedKeyManagerServer) AsymDecrypt(context.Context, *AsymDecryptRequest) (*AsymDecryptResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AsymDecrypt not implemented")
}
func (UnimplementedKeyManagerServer) Sign(context.Context, *SignRequest) (*SignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sign not implemented")
}
func (UnimplementedKeyManagerServer) Sm2SignWithSm3(context.Context, *Sm2SignWithSm3Request) (*Sm2SignWithSm3Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sm2SignWithSm3 not implemented")
}
func (UnimplementedKeyManagerServer) Sm2VerifyWithSm3(context.Context, *Sm2VerifyWithSm3Request) (*Sm2VerifyWithSm3Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sm2VerifyWithSm3 not implemented")
}
func (UnimplementedKeyManagerServer) IssueGmCert(context.Context, *IssueGmCertRequest) (*IssueGmCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IssueGmCert not implemented")
}
func (UnimplementedKeyManagerServer) RandomUint64(context.Context, *RandomUint64Request) (*RandomUint64Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RandomUint64 not implemented")
}
func (UnimplementedKeyManagerServer) SymEncrypt(context.Context, *SymEncryptRequest) (*SymEncryptResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SymEncrypt not implemented")
}
func (UnimplementedKeyManagerServer) SymDecrypt(context.Context, *SymDecryptRequest) (*SymDecryptResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SymDecrypt not implemented")
}
func (UnimplementedKeyManagerServer) mustEmbedUnimplementedKeyManagerServer() {}

// UnsafeKeyManagerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KeyManagerServer will
// result in compilation errors.
type UnsafeKeyManagerServer interface {
	mustEmbedUnimplementedKeyManagerServer()
}

func RegisterKeyManagerServer(s grpc.ServiceRegistrar, srv KeyManagerServer) {
	s.RegisterService(&KeyManager_ServiceDesc, srv)
}

func _KeyManager_Hash_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(KeyManagerServer).Hash(&keyManagerHashServer{stream})
}

type KeyManager_HashServer interface {
	SendAndClose(*HashResponse) error
	Recv() (*HashRequest, error)
	grpc.ServerStream
}

type keyManagerHashServer struct {
	grpc.ServerStream
}

func (x *keyManagerHashServer) SendAndClose(m *HashResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *keyManagerHashServer) Recv() (*HashRequest, error) {
	m := new(HashRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _KeyManager_AsymEncrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AsymEncryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).AsymEncrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/AsymEncrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).AsymEncrypt(ctx, req.(*AsymEncryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_AsymDecrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AsymDecryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).AsymDecrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/AsymDecrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).AsymDecrypt(ctx, req.(*AsymDecryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_Sign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).Sign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/Sign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).Sign(ctx, req.(*SignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_Sm2SignWithSm3_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Sm2SignWithSm3Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).Sm2SignWithSm3(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/Sm2SignWithSm3",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).Sm2SignWithSm3(ctx, req.(*Sm2SignWithSm3Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_Sm2VerifyWithSm3_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Sm2VerifyWithSm3Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).Sm2VerifyWithSm3(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/Sm2VerifyWithSm3",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).Sm2VerifyWithSm3(ctx, req.(*Sm2VerifyWithSm3Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_IssueGmCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IssueGmCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).IssueGmCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/IssueGmCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).IssueGmCert(ctx, req.(*IssueGmCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_RandomUint64_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RandomUint64Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).RandomUint64(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/RandomUint64",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).RandomUint64(ctx, req.(*RandomUint64Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_SymEncrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SymEncryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).SymEncrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/SymEncrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).SymEncrypt(ctx, req.(*SymEncryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_SymDecrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SymDecryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).SymDecrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datacloak.server.KeyManager/SymDecrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).SymDecrypt(ctx, req.(*SymDecryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// KeyManager_ServiceDesc is the grpc.ServiceDesc for KeyManager service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var KeyManager_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "datacloak.server.KeyManager",
	HandlerType: (*KeyManagerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AsymEncrypt",
			Handler:    _KeyManager_AsymEncrypt_Handler,
		},
		{
			MethodName: "AsymDecrypt",
			Handler:    _KeyManager_AsymDecrypt_Handler,
		},
		{
			MethodName: "Sign",
			Handler:    _KeyManager_Sign_Handler,
		},
		{
			MethodName: "Sm2SignWithSm3",
			Handler:    _KeyManager_Sm2SignWithSm3_Handler,
		},
		{
			MethodName: "Sm2VerifyWithSm3",
			Handler:    _KeyManager_Sm2VerifyWithSm3_Handler,
		},
		{
			MethodName: "IssueGmCert",
			Handler:    _KeyManager_IssueGmCert_Handler,
		},
		{
			MethodName: "RandomUint64",
			Handler:    _KeyManager_RandomUint64_Handler,
		},
		{
			MethodName: "SymEncrypt",
			Handler:    _KeyManager_SymEncrypt_Handler,
		},
		{
			MethodName: "SymDecrypt",
			Handler:    _KeyManager_SymDecrypt_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Hash",
			Handler:       _KeyManager_Hash_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "meili_proto/datacloak/server/key_manager.proto",
}
