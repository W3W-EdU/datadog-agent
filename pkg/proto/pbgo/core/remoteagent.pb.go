// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v4.24.4
// source: datadog/remoteagent/remoteagent.proto

package core

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RegistrationData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AgentId string `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
}

func (x *RegistrationData) Reset() {
	*x = RegistrationData{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegistrationData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegistrationData) ProtoMessage() {}

func (x *RegistrationData) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegistrationData.ProtoReflect.Descriptor instead.
func (*RegistrationData) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{0}
}

func (x *RegistrationData) GetAgentId() string {
	if x != nil {
		return x.AgentId
	}
	return ""
}

type StatusSection struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header string            `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Fields map[string]string `protobuf:"bytes,2,rep,name=fields,proto3" json:"fields,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *StatusSection) Reset() {
	*x = StatusSection{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusSection) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusSection) ProtoMessage() {}

func (x *StatusSection) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusSection.ProtoReflect.Descriptor instead.
func (*StatusSection) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{1}
}

func (x *StatusSection) GetHeader() string {
	if x != nil {
		return x.Header
	}
	return ""
}

func (x *StatusSection) GetFields() map[string]string {
	if x != nil {
		return x.Fields
	}
	return nil
}

type StatusData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AgentId       string                    `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	MainSection   *StatusSection            `protobuf:"bytes,2,opt,name=main_section,json=mainSection,proto3" json:"main_section,omitempty"`
	NamedSections map[string]*StatusSection `protobuf:"bytes,3,rep,name=named_sections,json=namedSections,proto3" json:"named_sections,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *StatusData) Reset() {
	*x = StatusData{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusData) ProtoMessage() {}

func (x *StatusData) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusData.ProtoReflect.Descriptor instead.
func (*StatusData) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{2}
}

func (x *StatusData) GetAgentId() string {
	if x != nil {
		return x.AgentId
	}
	return ""
}

func (x *StatusData) GetMainSection() *StatusSection {
	if x != nil {
		return x.MainSection
	}
	return nil
}

func (x *StatusData) GetNamedSections() map[string]*StatusSection {
	if x != nil {
		return x.NamedSections
	}
	return nil
}

type FlareData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AgentId string            `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	Files   map[string][]byte `protobuf:"bytes,2,rep,name=files,proto3" json:"files,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *FlareData) Reset() {
	*x = FlareData{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FlareData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlareData) ProtoMessage() {}

func (x *FlareData) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlareData.ProtoReflect.Descriptor instead.
func (*FlareData) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{3}
}

func (x *FlareData) GetAgentId() string {
	if x != nil {
		return x.AgentId
	}
	return ""
}

func (x *FlareData) GetFiles() map[string][]byte {
	if x != nil {
		return x.Files
	}
	return nil
}

type RegistrationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AgentId string `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
}

func (x *RegistrationResponse) Reset() {
	*x = RegistrationResponse{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegistrationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegistrationResponse) ProtoMessage() {}

func (x *RegistrationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegistrationResponse.ProtoReflect.Descriptor instead.
func (*RegistrationResponse) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{4}
}

func (x *RegistrationResponse) GetAgentId() string {
	if x != nil {
		return x.AgentId
	}
	return ""
}

type StatusRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AgentId string `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
}

func (x *StatusRequest) Reset() {
	*x = StatusRequest{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusRequest) ProtoMessage() {}

func (x *StatusRequest) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusRequest.ProtoReflect.Descriptor instead.
func (*StatusRequest) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{5}
}

func (x *StatusRequest) GetAgentId() string {
	if x != nil {
		return x.AgentId
	}
	return ""
}

type FlareRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AgentId string `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
}

func (x *FlareRequest) Reset() {
	*x = FlareRequest{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FlareRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlareRequest) ProtoMessage() {}

func (x *FlareRequest) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlareRequest.ProtoReflect.Descriptor instead.
func (*FlareRequest) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{6}
}

func (x *FlareRequest) GetAgentId() string {
	if x != nil {
		return x.AgentId
	}
	return ""
}

type UpdateRemoteAgentStreamRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Payload:
	//
	//	*UpdateRemoteAgentStreamRequest_Register
	//	*UpdateRemoteAgentStreamRequest_Status
	//	*UpdateRemoteAgentStreamRequest_Flare
	Payload isUpdateRemoteAgentStreamRequest_Payload `protobuf_oneof:"payload"`
}

func (x *UpdateRemoteAgentStreamRequest) Reset() {
	*x = UpdateRemoteAgentStreamRequest{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UpdateRemoteAgentStreamRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateRemoteAgentStreamRequest) ProtoMessage() {}

func (x *UpdateRemoteAgentStreamRequest) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateRemoteAgentStreamRequest.ProtoReflect.Descriptor instead.
func (*UpdateRemoteAgentStreamRequest) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{7}
}

func (m *UpdateRemoteAgentStreamRequest) GetPayload() isUpdateRemoteAgentStreamRequest_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (x *UpdateRemoteAgentStreamRequest) GetRegister() *RegistrationData {
	if x, ok := x.GetPayload().(*UpdateRemoteAgentStreamRequest_Register); ok {
		return x.Register
	}
	return nil
}

func (x *UpdateRemoteAgentStreamRequest) GetStatus() *StatusData {
	if x, ok := x.GetPayload().(*UpdateRemoteAgentStreamRequest_Status); ok {
		return x.Status
	}
	return nil
}

func (x *UpdateRemoteAgentStreamRequest) GetFlare() *FlareData {
	if x, ok := x.GetPayload().(*UpdateRemoteAgentStreamRequest_Flare); ok {
		return x.Flare
	}
	return nil
}

type isUpdateRemoteAgentStreamRequest_Payload interface {
	isUpdateRemoteAgentStreamRequest_Payload()
}

type UpdateRemoteAgentStreamRequest_Register struct {
	Register *RegistrationData `protobuf:"bytes,1,opt,name=register,proto3,oneof"`
}

type UpdateRemoteAgentStreamRequest_Status struct {
	Status *StatusData `protobuf:"bytes,2,opt,name=status,proto3,oneof"`
}

type UpdateRemoteAgentStreamRequest_Flare struct {
	Flare *FlareData `protobuf:"bytes,3,opt,name=flare,proto3,oneof"`
}

func (*UpdateRemoteAgentStreamRequest_Register) isUpdateRemoteAgentStreamRequest_Payload() {}

func (*UpdateRemoteAgentStreamRequest_Status) isUpdateRemoteAgentStreamRequest_Payload() {}

func (*UpdateRemoteAgentStreamRequest_Flare) isUpdateRemoteAgentStreamRequest_Payload() {}

type UpdateRemoteAgentStreamResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Payload:
	//
	//	*UpdateRemoteAgentStreamResponse_Register
	//	*UpdateRemoteAgentStreamResponse_KeepAlive
	//	*UpdateRemoteAgentStreamResponse_Status
	//	*UpdateRemoteAgentStreamResponse_Flare
	Payload isUpdateRemoteAgentStreamResponse_Payload `protobuf_oneof:"payload"`
}

func (x *UpdateRemoteAgentStreamResponse) Reset() {
	*x = UpdateRemoteAgentStreamResponse{}
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UpdateRemoteAgentStreamResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateRemoteAgentStreamResponse) ProtoMessage() {}

func (x *UpdateRemoteAgentStreamResponse) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_remoteagent_remoteagent_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateRemoteAgentStreamResponse.ProtoReflect.Descriptor instead.
func (*UpdateRemoteAgentStreamResponse) Descriptor() ([]byte, []int) {
	return file_datadog_remoteagent_remoteagent_proto_rawDescGZIP(), []int{8}
}

func (m *UpdateRemoteAgentStreamResponse) GetPayload() isUpdateRemoteAgentStreamResponse_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (x *UpdateRemoteAgentStreamResponse) GetRegister() *RegistrationResponse {
	if x, ok := x.GetPayload().(*UpdateRemoteAgentStreamResponse_Register); ok {
		return x.Register
	}
	return nil
}

func (x *UpdateRemoteAgentStreamResponse) GetKeepAlive() string {
	if x, ok := x.GetPayload().(*UpdateRemoteAgentStreamResponse_KeepAlive); ok {
		return x.KeepAlive
	}
	return ""
}

func (x *UpdateRemoteAgentStreamResponse) GetStatus() *StatusRequest {
	if x, ok := x.GetPayload().(*UpdateRemoteAgentStreamResponse_Status); ok {
		return x.Status
	}
	return nil
}

func (x *UpdateRemoteAgentStreamResponse) GetFlare() *FlareRequest {
	if x, ok := x.GetPayload().(*UpdateRemoteAgentStreamResponse_Flare); ok {
		return x.Flare
	}
	return nil
}

type isUpdateRemoteAgentStreamResponse_Payload interface {
	isUpdateRemoteAgentStreamResponse_Payload()
}

type UpdateRemoteAgentStreamResponse_Register struct {
	Register *RegistrationResponse `protobuf:"bytes,1,opt,name=register,proto3,oneof"`
}

type UpdateRemoteAgentStreamResponse_KeepAlive struct {
	KeepAlive string `protobuf:"bytes,2,opt,name=keep_alive,json=keepAlive,proto3,oneof"`
}

type UpdateRemoteAgentStreamResponse_Status struct {
	Status *StatusRequest `protobuf:"bytes,3,opt,name=status,proto3,oneof"`
}

type UpdateRemoteAgentStreamResponse_Flare struct {
	Flare *FlareRequest `protobuf:"bytes,4,opt,name=flare,proto3,oneof"`
}

func (*UpdateRemoteAgentStreamResponse_Register) isUpdateRemoteAgentStreamResponse_Payload() {}

func (*UpdateRemoteAgentStreamResponse_KeepAlive) isUpdateRemoteAgentStreamResponse_Payload() {}

func (*UpdateRemoteAgentStreamResponse_Status) isUpdateRemoteAgentStreamResponse_Payload() {}

func (*UpdateRemoteAgentStreamResponse_Flare) isUpdateRemoteAgentStreamResponse_Payload() {}

var File_datadog_remoteagent_remoteagent_proto protoreflect.FileDescriptor

var file_datadog_remoteagent_remoteagent_proto_rawDesc = []byte{
	0x0a, 0x25, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67,
	0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x22, 0x2d, 0x0a, 0x10,
	0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61,
	0x12, 0x19, 0x0a, 0x08, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x22, 0xaa, 0x01, 0x0a, 0x0d,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a,
	0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x46, 0x0a, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e,
	0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x1a, 0x39, 0x0a,
	0x0b, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xaf, 0x02, 0x0a, 0x0a, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x44, 0x61, 0x74, 0x61, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x49, 0x64, 0x12, 0x45, 0x0a, 0x0c, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x73, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64,
	0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x6d, 0x61,
	0x69, 0x6e, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x59, 0x0a, 0x0e, 0x6e, 0x61, 0x6d,
	0x65, 0x64, 0x5f, 0x73, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x32, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f,
	0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x44, 0x61,
	0x74, 0x61, 0x2e, 0x4e, 0x61, 0x6d, 0x65, 0x64, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0d, 0x6e, 0x61, 0x6d, 0x65, 0x64, 0x53, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x64, 0x0a, 0x12, 0x4e, 0x61, 0x6d, 0x65, 0x64, 0x53, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x38, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x64, 0x61,
	0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e,
	0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xa1, 0x01, 0x0a, 0x09, 0x46,
	0x6c, 0x61, 0x72, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x67, 0x65, 0x6e,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x67, 0x65, 0x6e,
	0x74, 0x49, 0x64, 0x12, 0x3f, 0x0a, 0x05, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x29, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d,
	0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x46, 0x6c, 0x61, 0x72, 0x65, 0x44, 0x61,
	0x74, 0x61, 0x2e, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x05, 0x66,
	0x69, 0x6c, 0x65, 0x73, 0x1a, 0x38, 0x0a, 0x0a, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x31,
	0x0a, 0x14, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x49,
	0x64, 0x22, 0x2a, 0x0a, 0x0d, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x22, 0x29, 0x0a,
	0x0c, 0x46, 0x6c, 0x61, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a,
	0x08, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x22, 0xe3, 0x01, 0x0a, 0x1e, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x53, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x43, 0x0a, 0x08, 0x72,
	0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e,
	0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67,
	0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x44, 0x61, 0x74, 0x61, 0x48, 0x00, 0x52, 0x08, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72,
	0x12, 0x39, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1f, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74,
	0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x44, 0x61, 0x74,
	0x61, 0x48, 0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x36, 0x0a, 0x05, 0x66,
	0x6c, 0x61, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x64, 0x61, 0x74,
	0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x2e, 0x46, 0x6c, 0x61, 0x72, 0x65, 0x44, 0x61, 0x74, 0x61, 0x48, 0x00, 0x52, 0x05, 0x66, 0x6c,
	0x61, 0x72, 0x65, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x8f,
	0x02, 0x0a, 0x1f, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x41,
	0x67, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x47, 0x0a, 0x08, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72,
	0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73,
	0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48,
	0x00, 0x52, 0x08, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x12, 0x1f, 0x0a, 0x0a, 0x6b,
	0x65, 0x65, 0x70, 0x5f, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x09, 0x6b, 0x65, 0x65, 0x70, 0x41, 0x6c, 0x69, 0x76, 0x65, 0x12, 0x3c, 0x0a, 0x06,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x64,
	0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65,
	0x6e, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x48, 0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x39, 0x0a, 0x05, 0x66, 0x6c,
	0x61, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e,
	0x46, 0x6c, 0x61, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x05,
	0x66, 0x6c, 0x61, 0x72, 0x65, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x42, 0x15, 0x5a, 0x13, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x70, 0x62,
	0x67, 0x6f, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_datadog_remoteagent_remoteagent_proto_rawDescOnce sync.Once
	file_datadog_remoteagent_remoteagent_proto_rawDescData = file_datadog_remoteagent_remoteagent_proto_rawDesc
)

func file_datadog_remoteagent_remoteagent_proto_rawDescGZIP() []byte {
	file_datadog_remoteagent_remoteagent_proto_rawDescOnce.Do(func() {
		file_datadog_remoteagent_remoteagent_proto_rawDescData = protoimpl.X.CompressGZIP(file_datadog_remoteagent_remoteagent_proto_rawDescData)
	})
	return file_datadog_remoteagent_remoteagent_proto_rawDescData
}

var file_datadog_remoteagent_remoteagent_proto_msgTypes = make([]protoimpl.MessageInfo, 12)
var file_datadog_remoteagent_remoteagent_proto_goTypes = []any{
	(*RegistrationData)(nil),                // 0: datadog.remoteagent.RegistrationData
	(*StatusSection)(nil),                   // 1: datadog.remoteagent.StatusSection
	(*StatusData)(nil),                      // 2: datadog.remoteagent.StatusData
	(*FlareData)(nil),                       // 3: datadog.remoteagent.FlareData
	(*RegistrationResponse)(nil),            // 4: datadog.remoteagent.RegistrationResponse
	(*StatusRequest)(nil),                   // 5: datadog.remoteagent.StatusRequest
	(*FlareRequest)(nil),                    // 6: datadog.remoteagent.FlareRequest
	(*UpdateRemoteAgentStreamRequest)(nil),  // 7: datadog.remoteagent.UpdateRemoteAgentStreamRequest
	(*UpdateRemoteAgentStreamResponse)(nil), // 8: datadog.remoteagent.UpdateRemoteAgentStreamResponse
	nil,                                     // 9: datadog.remoteagent.StatusSection.FieldsEntry
	nil,                                     // 10: datadog.remoteagent.StatusData.NamedSectionsEntry
	nil,                                     // 11: datadog.remoteagent.FlareData.FilesEntry
}
var file_datadog_remoteagent_remoteagent_proto_depIdxs = []int32{
	9,  // 0: datadog.remoteagent.StatusSection.fields:type_name -> datadog.remoteagent.StatusSection.FieldsEntry
	1,  // 1: datadog.remoteagent.StatusData.main_section:type_name -> datadog.remoteagent.StatusSection
	10, // 2: datadog.remoteagent.StatusData.named_sections:type_name -> datadog.remoteagent.StatusData.NamedSectionsEntry
	11, // 3: datadog.remoteagent.FlareData.files:type_name -> datadog.remoteagent.FlareData.FilesEntry
	0,  // 4: datadog.remoteagent.UpdateRemoteAgentStreamRequest.register:type_name -> datadog.remoteagent.RegistrationData
	2,  // 5: datadog.remoteagent.UpdateRemoteAgentStreamRequest.status:type_name -> datadog.remoteagent.StatusData
	3,  // 6: datadog.remoteagent.UpdateRemoteAgentStreamRequest.flare:type_name -> datadog.remoteagent.FlareData
	4,  // 7: datadog.remoteagent.UpdateRemoteAgentStreamResponse.register:type_name -> datadog.remoteagent.RegistrationResponse
	5,  // 8: datadog.remoteagent.UpdateRemoteAgentStreamResponse.status:type_name -> datadog.remoteagent.StatusRequest
	6,  // 9: datadog.remoteagent.UpdateRemoteAgentStreamResponse.flare:type_name -> datadog.remoteagent.FlareRequest
	1,  // 10: datadog.remoteagent.StatusData.NamedSectionsEntry.value:type_name -> datadog.remoteagent.StatusSection
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_datadog_remoteagent_remoteagent_proto_init() }
func file_datadog_remoteagent_remoteagent_proto_init() {
	if File_datadog_remoteagent_remoteagent_proto != nil {
		return
	}
	file_datadog_remoteagent_remoteagent_proto_msgTypes[7].OneofWrappers = []any{
		(*UpdateRemoteAgentStreamRequest_Register)(nil),
		(*UpdateRemoteAgentStreamRequest_Status)(nil),
		(*UpdateRemoteAgentStreamRequest_Flare)(nil),
	}
	file_datadog_remoteagent_remoteagent_proto_msgTypes[8].OneofWrappers = []any{
		(*UpdateRemoteAgentStreamResponse_Register)(nil),
		(*UpdateRemoteAgentStreamResponse_KeepAlive)(nil),
		(*UpdateRemoteAgentStreamResponse_Status)(nil),
		(*UpdateRemoteAgentStreamResponse_Flare)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_datadog_remoteagent_remoteagent_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   12,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_datadog_remoteagent_remoteagent_proto_goTypes,
		DependencyIndexes: file_datadog_remoteagent_remoteagent_proto_depIdxs,
		MessageInfos:      file_datadog_remoteagent_remoteagent_proto_msgTypes,
	}.Build()
	File_datadog_remoteagent_remoteagent_proto = out.File
	file_datadog_remoteagent_remoteagent_proto_rawDesc = nil
	file_datadog_remoteagent_remoteagent_proto_goTypes = nil
	file_datadog_remoteagent_remoteagent_proto_depIdxs = nil
}
