package client

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	pb "key_manager_client/meili_proto/datacloak/server"
	"log"
	"sync"
	"time"
)

type KmClient struct {
	conn *grpc.ClientConn
	addr string
	mu   sync.Mutex
}

func NewKmClient(addr string) *KmClient {
	c := &KmClient{
		conn: nil,
		addr: addr,
	}
	return c
}

func (c *KmClient) Reconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil && c.conn.GetState() != connectivity.Ready {
		if err := c.conn.Close(); err != nil {
			log.Printf("conn to[%s] close error: %s", c.addr, err)
		}
	}
	conn, err := grpc.Dial(c.addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Printf("conn to[%s] init failed: %s", c.addr, err)
		return err
	}
	c.conn = conn
	return nil
}

func (c *KmClient) Close() {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Printf("conn[%s] close failed: %s", c.addr, err)
		}
	}
}

func (c *KmClient) Hash(msg string) ([]byte, error) {
	err := c.Reconnect()
	if err != nil {
		return nil, err
	}
	client := pb.NewKeyManagerClient(c.conn)
	req := pb.HashRequest{
		Type: pb.CryptoAlgType_SM3,
		Msg:  []byte(msg),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	stream, err := client.Hash(ctx)
	if err != nil {
		log.Printf("new hash stream failed: %s", err)
		return nil, err
	}
	err = stream.Send(&req)
	if err != nil {
		log.Printf("hash send failed: %s", err)
		return nil, err
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		log.Printf("Hash CloseAndRecv failed: %s", err)
		return nil, err
	}
	if resp.ErrorCode != pb.DataCloakErrorCode_DC_OK {
		errmsg := fmt.Sprintf("Hash error code[%s], error message[%s]", resp.ErrorCode.String(), resp.ErrorMessage)
		log.Println(errmsg)
		return nil, errors.New(errmsg)
	}
	return resp.Msg, nil
}

func (c *KmClient) Sm2SignWithSm3(msg, priIdx string) ([]byte, error) {
	err := c.Reconnect()
	if err != nil {
		return nil, err
	}
	client := pb.NewKeyManagerClient(c.conn)
	req := pb.Sm2SignWithSm3Request{
		Msg:    []byte(msg),
		PriKey: priIdx,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	resp, err := client.Sm2SignWithSm3(ctx, &req)
	if err != nil {
		log.Printf("Sm2SignWithSm3 failed: %s", err)
		return nil, err
	}
	if resp.ErrorCode != pb.DataCloakErrorCode_DC_OK {
		errmsg := fmt.Sprintf("Hash error code[%s], error message[%s]", resp.ErrorCode.String(), resp.ErrorMessage)
		log.Println(errmsg)
		return nil, errors.New(errmsg)
	}
	return resp.Msg, nil
}

func (c *KmClient) Sm2VerifyWithSm3(msg, priIdx string, sig []byte) (bool, error) {
	err := c.Reconnect()
	if err != nil {
		return false, err
	}
	client := pb.NewKeyManagerClient(c.conn)
	req := pb.Sm2VerifyWithSm3Request{
		Msg:    []byte(msg),
		PriKey: priIdx,
		Sig:    sig,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	resp, err := client.Sm2VerifyWithSm3(ctx, &req)
	if err != nil {
		log.Printf("Sm2VerifyWithSm3 failed: %s", err)
		return false, err
	}
	if resp.ErrorCode != pb.DataCloakErrorCode_DC_OK {
		errmsg := fmt.Sprintf("Sm2VerifyWithSm3 error code[%s], error message[%s]", resp.ErrorCode.String(), resp.ErrorMessage)
		log.Println(errmsg)
		return false, errors.New(errmsg)
	}
	return resp.ErrorCode == pb.DataCloakErrorCode_DC_OK, nil
}

func (c *KmClient) IssueCert(cname, pub string) (string, error) {
	err := c.Reconnect()
	if err != nil {
		return "", err
	}
	client := pb.NewKeyManagerClient(c.conn)
	req := pb.IssueGmCertRequest{
		Cname:        cname,
		ClientPubPem: pub,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	resp, err := client.IssueGmCert(ctx, &req)
	if err != nil {
		log.Printf("IssueCert failed: %s", err)
		return "", err
	}
	if resp.ErrorCode != pb.DataCloakErrorCode_DC_OK {
		errmsg := fmt.Sprintf("IssueCert error code[%s], error message[%s]", resp.ErrorCode.String(), resp.ErrorMessage)
		log.Println(errmsg)
		return "", errors.New(errmsg)
	}
	return resp.CertPem, nil
}
