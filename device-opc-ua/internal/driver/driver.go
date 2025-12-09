// -*- Mode: Go; indent-tabs-mode: t -*-
//
// Copyright (C) 2018 Canonical Ltd
// Copyright (C) 2018 IOTech Ltd
// Copyright (C) 2021 Schneider Electric
// Copyright (C) 2024 YIQISOFT
//
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"os"
	"sync"

	"github.com/edgexfoundry/device-sdk-go/v4/pkg/interfaces"
	sdkModel "github.com/edgexfoundry/device-sdk-go/v4/pkg/models"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/errors"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/models"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
)

var once sync.Once
var driver *Driver

const (
	clientCertPath = "/run/edgex/secrets/device-opcua/certs/opc-client-cert.pem"
	clientKeyPath  = "/run/edgex/secrets/device-opcua/certs/opc-client-key.pem"
	trustStorePath = "/run/edgex/secrets/device-opcua/truststore/"
)

// Driver struct
type Driver struct {
	Logger        logger.LoggingClient
	AsyncCh       chan<- *sdkModel.AsyncValues
	sdkService    interfaces.DeviceServiceSDK
	serviceConfig *ServiceConfig
	resourceMap   map[uint32]string
	mu            sync.Mutex
	ctxCancel     context.CancelFunc
	clientMap     map[string]*opcua.Client
}

// NewProtocolDriver returns a new protocol driver object
func NewProtocolDriver() interfaces.ProtocolDriver {
	once.Do(func() {
		driver = new(Driver)
	})
	return driver
}

// Initialize handles initial configuration loading
func (d *Driver) Initialize(sdk interfaces.DeviceServiceSDK) error {
	d.sdkService = sdk
	d.Logger = sdk.LoggingClient()
	d.AsyncCh = sdk.AsyncValuesChannel()
	d.serviceConfig = &ServiceConfig{}

	d.mu.Lock()
	d.resourceMap = make(map[uint32]string)
	d.clientMap = make(map[string]*opcua.Client)
	d.mu.Unlock()

	// Load custom config
	if err := sdk.LoadCustomConfig(d.serviceConfig, CustomConfigSectionName); err != nil {
		return err
	}

	if err := d.serviceConfig.OPCUAServer.Validate(); err != nil {
		return errors.NewCommonEdgeXWrapper(err)
	}

	if err := sdk.ListenForCustomConfigChanges(&d.serviceConfig.OPCUAServer.Writable, WritableInfoSectionName, d.updateWritableConfig); err != nil {
		return err
	}

	return nil
}

// Update configuration callback
func (d *Driver) updateWritableConfig(rawWritableConfig interface{}) {
	updated, ok := rawWritableConfig.(*WritableInfo)
	if !ok {
		return
	}

	d.cleanup()
	d.serviceConfig.OPCUAServer.Writable = *updated
	go d.startSubscriber()
}

func (d *Driver) startSubscriber() {
	_ = d.startSubscriptionListener()
}

func (d *Driver) cleanup() {
	if d.ctxCancel != nil {
		d.ctxCancel()
		d.ctxCancel = nil
	}
}

func (d *Driver) AddDevice(deviceName string, _ map[string]models.ProtocolProperties, _ models.AdminState) error {
	go d.startSubscriber()
	return nil
}

func (d *Driver) UpdateDevice(_ string, _ map[string]models.ProtocolProperties, _ models.AdminState) error {
	return nil
}

func (d *Driver) RemoveDevice(_ string, _ map[string]models.ProtocolProperties) error {
	return nil
}

func (d *Driver) Start() error {
	return nil
}

func (d *Driver) Stop(force bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, cli := range d.clientMap {
		cli.Close(context.Background())
	}
	return nil
}

func (d *Driver) Discover() error {
	return fmt.Errorf("discover not implemented")
}

func (d *Driver) ValidateDevice(device models.Device) error {
	_, err := FetchEndpoint(device.Protocols)
	return err
}

// Helper: Extract NodeId
func getNodeID(attrs map[string]interface{}, id string) (string, error) {
	v, ok := attrs[id]
	if !ok {
		return "", fmt.Errorf("attribute %s not found", id)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be string", id)
	}
	return s, nil
}

// Ensure client certificate exists – no auto-generation.
// It will FAIL if the files are missing or invalid.
func ensureClientCertificate() (*tls.Certificate, error) {
	if !fileExists(clientCertPath) || !fileExists(clientKeyPath) {
		return nil, fmt.Errorf(
			"client certificate or key missing. Expected cert at %s and key at %s",
			clientCertPath, clientKeyPath,
		)
	}

	c, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate/key: %w", err)
	}

	return &c, nil
}

// Helper: Check file
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Build secure OPC-UA Client
func (d *Driver) buildClient(ctx context.Context, endpoint string) (*opcua.Client, error) {
	d.mu.Lock()
	if cli, ok := d.clientMap[endpoint]; ok {
		d.mu.Unlock()
		return cli, nil
	}
	d.mu.Unlock()

	// Load certificate – must already exist
	cert, err := ensureClientCertificate()
	if err != nil {
		return nil, err
	}
	d.Logger.Infof("Using OPC UA Client certificate from %s", clientCertPath)

	// Retrieve secure endpoints
	endpoints, err := opcua.GetEndpoints(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	// Select secure policy
	var secureEP *ua.EndpointDescription
	secPolicy := ua.SecurityPolicyURIBasic256Sha256
	secMode := ua.MessageSecurityModeSignAndEncrypt

	for _, ep := range endpoints {
		if ep.SecurityPolicyURI == secPolicy && ep.SecurityMode == secMode {
			secureEP = ep
			break
		}
	}
	if secureEP == nil {
		return nil, fmt.Errorf("no secure OPCUA endpoint found supporting Basic256Sha256 + SignAndEncrypt")
	}

	// Automatically trust server certificate
	if secureEP.ServerCertificate != nil {
		_ = os.MkdirAll(trustStorePath, 0700)
		_ = os.WriteFile(trustStorePath+"server.der", secureEP.ServerCertificate, 0644)
		d.Logger.Infof("Trusted server certificate stored")
	}

	// Make sure the key really is RSA
	privKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("client private key is not RSA")
	}

	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(secureEP, ua.UserTokenTypeAnonymous),
		opcua.Certificate(cert.Certificate[0]),
		opcua.PrivateKey(privKey),
		opcua.AuthAnonymous(),
	}

	client, err := opcua.NewClient(endpoint, opts...)
	if err != nil {
		return nil, err
	}

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.clientMap[endpoint] = client
	d.mu.Unlock()

	d.Logger.Infof("🔐 Secure OPC UA Connection Established → %s", endpoint)
	return client, nil
}
