// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/openservicemesh/osm/pkg/configurator (interfaces: Configurator)

// Package configurator is a generated GoMock package.
package configurator

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	v1alpha2 "github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	auth "github.com/openservicemesh/osm/pkg/auth"
	v1 "k8s.io/api/core/v1"
)

// MockConfigurator is a mock of Configurator interface.
type MockConfigurator struct {
	ctrl     *gomock.Controller
	recorder *MockConfiguratorMockRecorder
}

// MockConfiguratorMockRecorder is the mock recorder for MockConfigurator.
type MockConfiguratorMockRecorder struct {
	mock *MockConfigurator
}

// NewMockConfigurator creates a new mock instance.
func NewMockConfigurator(ctrl *gomock.Controller) *MockConfigurator {
	mock := &MockConfigurator{ctrl: ctrl}
	mock.recorder = &MockConfiguratorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConfigurator) EXPECT() *MockConfiguratorMockRecorder {
	return m.recorder
}

// GetCertKeyBitSize mocks base method.
func (m *MockConfigurator) GetCertKeyBitSize() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCertKeyBitSize")
	ret0, _ := ret[0].(int)
	return ret0
}

// GetCertKeyBitSize indicates an expected call of GetCertKeyBitSize.
func (mr *MockConfiguratorMockRecorder) GetCertKeyBitSize() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCertKeyBitSize", reflect.TypeOf((*MockConfigurator)(nil).GetCertKeyBitSize))
}

// GetConfigResyncInterval mocks base method.
func (m *MockConfigurator) GetConfigResyncInterval() time.Duration {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConfigResyncInterval")
	ret0, _ := ret[0].(time.Duration)
	return ret0
}

// GetConfigResyncInterval indicates an expected call of GetConfigResyncInterval.
func (mr *MockConfiguratorMockRecorder) GetConfigResyncInterval() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConfigResyncInterval", reflect.TypeOf((*MockConfigurator)(nil).GetConfigResyncInterval))
}

// GetFeatureFlags mocks base method.
func (m *MockConfigurator) GetFeatureFlags() v1alpha2.FeatureFlags {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFeatureFlags")
	ret0, _ := ret[0].(v1alpha2.FeatureFlags)
	return ret0
}

// GetFeatureFlags indicates an expected call of GetFeatureFlags.
func (mr *MockConfiguratorMockRecorder) GetFeatureFlags() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFeatureFlags", reflect.TypeOf((*MockConfigurator)(nil).GetFeatureFlags))
}

// GetInboundExternalAuthConfig mocks base method.
func (m *MockConfigurator) GetInboundExternalAuthConfig() auth.ExtAuthConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInboundExternalAuthConfig")
	ret0, _ := ret[0].(auth.ExtAuthConfig)
	return ret0
}

// GetInboundExternalAuthConfig indicates an expected call of GetInboundExternalAuthConfig.
func (mr *MockConfiguratorMockRecorder) GetInboundExternalAuthConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInboundExternalAuthConfig", reflect.TypeOf((*MockConfigurator)(nil).GetInboundExternalAuthConfig))
}

// GetInitContainerImage mocks base method.
func (m *MockConfigurator) GetInitContainerImage() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInitContainerImage")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetInitContainerImage indicates an expected call of GetInitContainerImage.
func (mr *MockConfiguratorMockRecorder) GetInitContainerImage() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInitContainerImage", reflect.TypeOf((*MockConfigurator)(nil).GetInitContainerImage))
}

// GetMaxDataPlaneConnections mocks base method.
func (m *MockConfigurator) GetMaxDataPlaneConnections() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMaxDataPlaneConnections")
	ret0, _ := ret[0].(int)
	return ret0
}

// GetMaxDataPlaneConnections indicates an expected call of GetMaxDataPlaneConnections.
func (mr *MockConfiguratorMockRecorder) GetMaxDataPlaneConnections() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMaxDataPlaneConnections", reflect.TypeOf((*MockConfigurator)(nil).GetMaxDataPlaneConnections))
}

// GetMeshConfig mocks base method.
func (m *MockConfigurator) GetMeshConfig() v1alpha2.MeshConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMeshConfig")
	ret0, _ := ret[0].(v1alpha2.MeshConfig)
	return ret0
}

// GetMeshConfig indicates an expected call of GetMeshConfig.
func (mr *MockConfiguratorMockRecorder) GetMeshConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMeshConfig", reflect.TypeOf((*MockConfigurator)(nil).GetMeshConfig))
}

// GetMeshConfigJSON mocks base method.
func (m *MockConfigurator) GetMeshConfigJSON() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMeshConfigJSON")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMeshConfigJSON indicates an expected call of GetMeshConfigJSON.
func (mr *MockConfiguratorMockRecorder) GetMeshConfigJSON() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMeshConfigJSON", reflect.TypeOf((*MockConfigurator)(nil).GetMeshConfigJSON))
}

// GetOSMLogLevel mocks base method.
func (m *MockConfigurator) GetOSMLogLevel() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOSMLogLevel")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetOSMLogLevel indicates an expected call of GetOSMLogLevel.
func (mr *MockConfiguratorMockRecorder) GetOSMLogLevel() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOSMLogLevel", reflect.TypeOf((*MockConfigurator)(nil).GetOSMLogLevel))
}

// GetOSMNamespace mocks base method.
func (m *MockConfigurator) GetOSMNamespace() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOSMNamespace")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetOSMNamespace indicates an expected call of GetOSMNamespace.
func (mr *MockConfiguratorMockRecorder) GetOSMNamespace() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOSMNamespace", reflect.TypeOf((*MockConfigurator)(nil).GetOSMNamespace))
}

// GetProxyResources mocks base method.
func (m *MockConfigurator) GetProxyResources() v1.ResourceRequirements {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProxyResources")
	ret0, _ := ret[0].(v1.ResourceRequirements)
	return ret0
}

// GetProxyResources indicates an expected call of GetProxyResources.
func (mr *MockConfiguratorMockRecorder) GetProxyResources() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProxyResources", reflect.TypeOf((*MockConfigurator)(nil).GetProxyResources))
}

// GetProxyServerPort mocks base method.
func (m *MockConfigurator) GetProxyServerPort() uint32 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProxyServerPort")
	ret0, _ := ret[0].(uint32)
	return ret0
}

// GetProxyServerPort indicates an expected call of GetProxyServerPort.
func (mr *MockConfiguratorMockRecorder) GetProxyServerPort() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProxyServerPort", reflect.TypeOf((*MockConfigurator)(nil).GetProxyServerPort))
}

// GetRemoteLoggingAuthorization mocks base method.
func (m *MockConfigurator) GetRemoteLoggingAuthorization() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRemoteLoggingAuthorization")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetRemoteLoggingAuthorization indicates an expected call of GetRemoteLoggingAuthorization.
func (mr *MockConfiguratorMockRecorder) GetRemoteLoggingAuthorization() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRemoteLoggingAuthorization", reflect.TypeOf((*MockConfigurator)(nil).GetRemoteLoggingAuthorization))
}

// GetRemoteLoggingEndpoint mocks base method.
func (m *MockConfigurator) GetRemoteLoggingEndpoint() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRemoteLoggingEndpoint")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetRemoteLoggingEndpoint indicates an expected call of GetRemoteLoggingEndpoint.
func (mr *MockConfiguratorMockRecorder) GetRemoteLoggingEndpoint() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRemoteLoggingEndpoint", reflect.TypeOf((*MockConfigurator)(nil).GetRemoteLoggingEndpoint))
}

// GetRemoteLoggingHost mocks base method.
func (m *MockConfigurator) GetRemoteLoggingHost() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRemoteLoggingHost")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetRemoteLoggingHost indicates an expected call of GetRemoteLoggingHost.
func (mr *MockConfiguratorMockRecorder) GetRemoteLoggingHost() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRemoteLoggingHost", reflect.TypeOf((*MockConfigurator)(nil).GetRemoteLoggingHost))
}

// GetRemoteLoggingPort mocks base method.
func (m *MockConfigurator) GetRemoteLoggingPort() uint32 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRemoteLoggingPort")
	ret0, _ := ret[0].(uint32)
	return ret0
}

// GetRemoteLoggingPort indicates an expected call of GetRemoteLoggingPort.
func (mr *MockConfiguratorMockRecorder) GetRemoteLoggingPort() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRemoteLoggingPort", reflect.TypeOf((*MockConfigurator)(nil).GetRemoteLoggingPort))
}

// GetServiceCertValidityPeriod mocks base method.
func (m *MockConfigurator) GetServiceCertValidityPeriod() time.Duration {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServiceCertValidityPeriod")
	ret0, _ := ret[0].(time.Duration)
	return ret0
}

// GetServiceCertValidityPeriod indicates an expected call of GetServiceCertValidityPeriod.
func (mr *MockConfiguratorMockRecorder) GetServiceCertValidityPeriod() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceCertValidityPeriod", reflect.TypeOf((*MockConfigurator)(nil).GetServiceCertValidityPeriod))
}

// GetSidecarClass mocks base method.
func (m *MockConfigurator) GetSidecarClass() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSidecarClass")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetSidecarClass indicates an expected call of GetSidecarClass.
func (mr *MockConfiguratorMockRecorder) GetSidecarClass() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSidecarClass", reflect.TypeOf((*MockConfigurator)(nil).GetSidecarClass))
}

// GetSidecarDisabledMTLS mocks base method.
func (m *MockConfigurator) GetSidecarDisabledMTLS() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSidecarDisabledMTLS")
	ret0, _ := ret[0].(bool)
	return ret0
}

// GetSidecarDisabledMTLS indicates an expected call of GetSidecarDisabledMTLS.
func (mr *MockConfiguratorMockRecorder) GetSidecarDisabledMTLS() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSidecarDisabledMTLS", reflect.TypeOf((*MockConfigurator)(nil).GetSidecarDisabledMTLS))
}

// GetSidecarImage mocks base method.
func (m *MockConfigurator) GetSidecarImage() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSidecarImage")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetSidecarImage indicates an expected call of GetSidecarImage.
func (mr *MockConfiguratorMockRecorder) GetSidecarImage() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSidecarImage", reflect.TypeOf((*MockConfigurator)(nil).GetSidecarImage))
}

// GetSidecarLogLevel mocks base method.
func (m *MockConfigurator) GetSidecarLogLevel() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSidecarLogLevel")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetSidecarLogLevel indicates an expected call of GetSidecarLogLevel.
func (mr *MockConfiguratorMockRecorder) GetSidecarLogLevel() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSidecarLogLevel", reflect.TypeOf((*MockConfigurator)(nil).GetSidecarLogLevel))
}

// GetSidecarWindowsImage mocks base method.
func (m *MockConfigurator) GetSidecarWindowsImage() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSidecarWindowsImage")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetSidecarWindowsImage indicates an expected call of GetSidecarWindowsImage.
func (mr *MockConfiguratorMockRecorder) GetSidecarWindowsImage() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSidecarWindowsImage", reflect.TypeOf((*MockConfigurator)(nil).GetSidecarWindowsImage))
}

// GetTracingEndpoint mocks base method.
func (m *MockConfigurator) GetTracingEndpoint() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTracingEndpoint")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetTracingEndpoint indicates an expected call of GetTracingEndpoint.
func (mr *MockConfiguratorMockRecorder) GetTracingEndpoint() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTracingEndpoint", reflect.TypeOf((*MockConfigurator)(nil).GetTracingEndpoint))
}

// GetTracingHost mocks base method.
func (m *MockConfigurator) GetTracingHost() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTracingHost")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetTracingHost indicates an expected call of GetTracingHost.
func (mr *MockConfiguratorMockRecorder) GetTracingHost() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTracingHost", reflect.TypeOf((*MockConfigurator)(nil).GetTracingHost))
}

// GetTracingPort mocks base method.
func (m *MockConfigurator) GetTracingPort() uint32 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTracingPort")
	ret0, _ := ret[0].(uint32)
	return ret0
}

// GetTracingPort indicates an expected call of GetTracingPort.
func (mr *MockConfiguratorMockRecorder) GetTracingPort() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTracingPort", reflect.TypeOf((*MockConfigurator)(nil).GetTracingPort))
}

// IsDebugServerEnabled mocks base method.
func (m *MockConfigurator) IsDebugServerEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsDebugServerEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsDebugServerEnabled indicates an expected call of IsDebugServerEnabled.
func (mr *MockConfiguratorMockRecorder) IsDebugServerEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsDebugServerEnabled", reflect.TypeOf((*MockConfigurator)(nil).IsDebugServerEnabled))
}

// IsEgressEnabled mocks base method.
func (m *MockConfigurator) IsEgressEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsEgressEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsEgressEnabled indicates an expected call of IsEgressEnabled.
func (mr *MockConfiguratorMockRecorder) IsEgressEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsEgressEnabled", reflect.TypeOf((*MockConfigurator)(nil).IsEgressEnabled))
}

// IsPermissiveTrafficPolicyMode mocks base method.
func (m *MockConfigurator) IsPermissiveTrafficPolicyMode() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsPermissiveTrafficPolicyMode")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsPermissiveTrafficPolicyMode indicates an expected call of IsPermissiveTrafficPolicyMode.
func (mr *MockConfiguratorMockRecorder) IsPermissiveTrafficPolicyMode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsPermissiveTrafficPolicyMode", reflect.TypeOf((*MockConfigurator)(nil).IsPermissiveTrafficPolicyMode))
}

// IsPrivilegedInitContainer mocks base method.
func (m *MockConfigurator) IsPrivilegedInitContainer() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsPrivilegedInitContainer")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsPrivilegedInitContainer indicates an expected call of IsPrivilegedInitContainer.
func (mr *MockConfiguratorMockRecorder) IsPrivilegedInitContainer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsPrivilegedInitContainer", reflect.TypeOf((*MockConfigurator)(nil).IsPrivilegedInitContainer))
}

// IsRemoteLoggingEnabled mocks base method.
func (m *MockConfigurator) IsRemoteLoggingEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRemoteLoggingEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsRemoteLoggingEnabled indicates an expected call of IsRemoteLoggingEnabled.
func (mr *MockConfiguratorMockRecorder) IsRemoteLoggingEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRemoteLoggingEnabled", reflect.TypeOf((*MockConfigurator)(nil).IsRemoteLoggingEnabled))
}

// IsTracingEnabled mocks base method.
func (m *MockConfigurator) IsTracingEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsTracingEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsTracingEnabled indicates an expected call of IsTracingEnabled.
func (mr *MockConfiguratorMockRecorder) IsTracingEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsTracingEnabled", reflect.TypeOf((*MockConfigurator)(nil).IsTracingEnabled))
}
