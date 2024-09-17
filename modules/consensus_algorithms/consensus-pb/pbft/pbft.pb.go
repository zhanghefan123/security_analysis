// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.26.1
// source: pbft.proto

package pbft

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

type Step int32

const (
	Step_INIT        Step = 0
	Step_PRE_PREPARE Step = 1
	Step_PREPARE     Step = 2
	Step_COMMIT      Step = 3
	Step_REPLY       Step = 4
	Step_COMPLETE    Step = 5
)

// Enum value maps for Step.
var (
	Step_name = map[int32]string{
		0: "INIT",
		1: "PRE_PREPARE",
		2: "PREPARE",
		3: "COMMIT",
		4: "REPLY",
		5: "COMPLETE",
	}
	Step_value = map[string]int32{
		"INIT":        0,
		"PRE_PREPARE": 1,
		"PREPARE":     2,
		"COMMIT":      3,
		"REPLY":       4,
		"COMPLETE":    5,
	}
)

func (x Step) Enum() *Step {
	p := new(Step)
	*p = x
	return p
}

func (x Step) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Step) Descriptor() protoreflect.EnumDescriptor {
	return file_pbft_proto_enumTypes[0].Descriptor()
}

func (Step) Type() protoreflect.EnumType {
	return &file_pbft_proto_enumTypes[0]
}

func (x Step) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Step.Descriptor instead.
func (Step) EnumDescriptor() ([]byte, []int) {
	return file_pbft_proto_rawDescGZIP(), []int{0}
}

type PBFTMsgType int32

const (
	PBFTMsgType_MSG_PRE_PREPARE PBFTMsgType = 0
	PBFTMsgType_MSG_PREPARE     PBFTMsgType = 1
	PBFTMsgType_MSG_COMMIT      PBFTMsgType = 2
	PBFTMsgType_MSG_REPLY       PBFTMsgType = 3
)

// Enum value maps for PBFTMsgType.
var (
	PBFTMsgType_name = map[int32]string{
		0: "MSG_PRE_PREPARE",
		1: "MSG_PREPARE",
		2: "MSG_COMMIT",
		3: "MSG_REPLY",
	}
	PBFTMsgType_value = map[string]int32{
		"MSG_PRE_PREPARE": 0,
		"MSG_PREPARE":     1,
		"MSG_COMMIT":      2,
		"MSG_REPLY":       3,
	}
)

func (x PBFTMsgType) Enum() *PBFTMsgType {
	p := new(PBFTMsgType)
	*p = x
	return p
}

func (x PBFTMsgType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PBFTMsgType) Descriptor() protoreflect.EnumDescriptor {
	return file_pbft_proto_enumTypes[1].Descriptor()
}

func (PBFTMsgType) Type() protoreflect.EnumType {
	return &file_pbft_proto_enumTypes[1]
}

func (x PBFTMsgType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PBFTMsgType.Descriptor instead.
func (PBFTMsgType) EnumDescriptor() ([]byte, []int) {
	return file_pbft_proto_rawDescGZIP(), []int{1}
}

// 应该对应于 message Vote 的 Type 部分
type VoteType int32

const (
	VoteType_VOTE_PREPARE VoteType = 0
	VoteType_VOTE_COMMIT  VoteType = 1
	VoteType_VOTE_REPLY   VoteType = 2
)

// Enum value maps for VoteType.
var (
	VoteType_name = map[int32]string{
		0: "VOTE_PREPARE",
		1: "VOTE_COMMIT",
		2: "VOTE_REPLY",
	}
	VoteType_value = map[string]int32{
		"VOTE_PREPARE": 0,
		"VOTE_COMMIT":  1,
		"VOTE_REPLY":   2,
	}
)

func (x VoteType) Enum() *VoteType {
	p := new(VoteType)
	*p = x
	return p
}

func (x VoteType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (VoteType) Descriptor() protoreflect.EnumDescriptor {
	return file_pbft_proto_enumTypes[2].Descriptor()
}

func (VoteType) Type() protoreflect.EnumType {
	return &file_pbft_proto_enumTypes[2]
}

func (x VoteType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use VoteType.Descriptor instead.
func (VoteType) EnumDescriptor() ([]byte, []int) {
	return file_pbft_proto_rawDescGZIP(), []int{2}
}

type PBFTMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type PBFTMsgType `protobuf:"varint,1,opt,name=Type,proto3,enum=PBFTMsgType" json:"Type,omitempty"`
	Msg  []byte      `protobuf:"bytes,2,opt,name=Msg,proto3" json:"Msg,omitempty"`
}

func (x *PBFTMsg) Reset() {
	*x = PBFTMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbft_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PBFTMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PBFTMsg) ProtoMessage() {}

func (x *PBFTMsg) ProtoReflect() protoreflect.Message {
	mi := &file_pbft_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PBFTMsg.ProtoReflect.Descriptor instead.
func (*PBFTMsg) Descriptor() ([]byte, []int) {
	return file_pbft_proto_rawDescGZIP(), []int{0}
}

func (x *PBFTMsg) GetType() PBFTMsgType {
	if x != nil {
		return x.Type
	}
	return PBFTMsgType_MSG_PRE_PREPARE
}

func (x *PBFTMsg) GetMsg() []byte {
	if x != nil {
		return x.Msg
	}
	return nil
}

// 应该对应于 PBFTMsg 的 Msg 部分
type PrePrepare struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserId   string `protobuf:"bytes,1,opt,name=UserId,proto3" json:"UserId,omitempty"`
	AccessId string `protobuf:"bytes,2,opt,name=AccessId,proto3" json:"AccessId,omitempty"`
}

func (x *PrePrepare) Reset() {
	*x = PrePrepare{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbft_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PrePrepare) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PrePrepare) ProtoMessage() {}

func (x *PrePrepare) ProtoReflect() protoreflect.Message {
	mi := &file_pbft_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PrePrepare.ProtoReflect.Descriptor instead.
func (*PrePrepare) Descriptor() ([]byte, []int) {
	return file_pbft_proto_rawDescGZIP(), []int{1}
}

func (x *PrePrepare) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *PrePrepare) GetAccessId() string {
	if x != nil {
		return x.AccessId
	}
	return ""
}

// 应该对应于 PBFTMsg 的 Msg 部分
type Vote struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type     VoteType `protobuf:"varint,1,opt,name=Type,proto3,enum=VoteType" json:"Type,omitempty"`
	Voter    string   `protobuf:"bytes,2,opt,name=Voter,proto3" json:"Voter,omitempty"`
	UserId   string   `protobuf:"bytes,3,opt,name=UserId,proto3" json:"UserId,omitempty"`
	AccessId string   `protobuf:"bytes,4,opt,name=AccessId,proto3" json:"AccessId,omitempty"`
	Judge    bool     `protobuf:"varint,5,opt,name=Judge,proto3" json:"Judge,omitempty"`
}

func (x *Vote) Reset() {
	*x = Vote{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbft_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Vote) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Vote) ProtoMessage() {}

func (x *Vote) ProtoReflect() protoreflect.Message {
	mi := &file_pbft_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Vote.ProtoReflect.Descriptor instead.
func (*Vote) Descriptor() ([]byte, []int) {
	return file_pbft_proto_rawDescGZIP(), []int{2}
}

func (x *Vote) GetType() VoteType {
	if x != nil {
		return x.Type
	}
	return VoteType_VOTE_PREPARE
}

func (x *Vote) GetVoter() string {
	if x != nil {
		return x.Voter
	}
	return ""
}

func (x *Vote) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *Vote) GetAccessId() string {
	if x != nil {
		return x.AccessId
	}
	return ""
}

func (x *Vote) GetJudge() bool {
	if x != nil {
		return x.Judge
	}
	return false
}

var File_pbft_proto protoreflect.FileDescriptor

var file_pbft_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x70, 0x62, 0x66, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3d, 0x0a, 0x07,
	0x50, 0x42, 0x46, 0x54, 0x4d, 0x73, 0x67, 0x12, 0x20, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0c, 0x2e, 0x50, 0x42, 0x46, 0x54, 0x4d, 0x73, 0x67, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x4d, 0x73, 0x67,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x4d, 0x73, 0x67, 0x22, 0x40, 0x0a, 0x0a, 0x50,
	0x72, 0x65, 0x50, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x55, 0x73, 0x65,
	0x72, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x55, 0x73, 0x65, 0x72, 0x49,
	0x64, 0x12, 0x1a, 0x0a, 0x08, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x49, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x49, 0x64, 0x22, 0x85, 0x01,
	0x0a, 0x04, 0x56, 0x6f, 0x74, 0x65, 0x12, 0x1d, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x09, 0x2e, 0x56, 0x6f, 0x74, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52,
	0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x56, 0x6f, 0x74, 0x65, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x56, 0x6f, 0x74, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x55,
	0x73, 0x65, 0x72, 0x49, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x55, 0x73, 0x65,
	0x72, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x49, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x49, 0x64, 0x12,
	0x14, 0x0a, 0x05, 0x4a, 0x75, 0x64, 0x67, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05,
	0x4a, 0x75, 0x64, 0x67, 0x65, 0x2a, 0x53, 0x0a, 0x04, 0x53, 0x74, 0x65, 0x70, 0x12, 0x08, 0x0a,
	0x04, 0x49, 0x4e, 0x49, 0x54, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b, 0x50, 0x52, 0x45, 0x5f, 0x50,
	0x52, 0x45, 0x50, 0x41, 0x52, 0x45, 0x10, 0x01, 0x12, 0x0b, 0x0a, 0x07, 0x50, 0x52, 0x45, 0x50,
	0x41, 0x52, 0x45, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x43, 0x4f, 0x4d, 0x4d, 0x49, 0x54, 0x10,
	0x03, 0x12, 0x09, 0x0a, 0x05, 0x52, 0x45, 0x50, 0x4c, 0x59, 0x10, 0x04, 0x12, 0x0c, 0x0a, 0x08,
	0x43, 0x4f, 0x4d, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x10, 0x05, 0x2a, 0x52, 0x0a, 0x0b, 0x50, 0x42,
	0x46, 0x54, 0x4d, 0x73, 0x67, 0x54, 0x79, 0x70, 0x65, 0x12, 0x13, 0x0a, 0x0f, 0x4d, 0x53, 0x47,
	0x5f, 0x50, 0x52, 0x45, 0x5f, 0x50, 0x52, 0x45, 0x50, 0x41, 0x52, 0x45, 0x10, 0x00, 0x12, 0x0f,
	0x0a, 0x0b, 0x4d, 0x53, 0x47, 0x5f, 0x50, 0x52, 0x45, 0x50, 0x41, 0x52, 0x45, 0x10, 0x01, 0x12,
	0x0e, 0x0a, 0x0a, 0x4d, 0x53, 0x47, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x49, 0x54, 0x10, 0x02, 0x12,
	0x0d, 0x0a, 0x09, 0x4d, 0x53, 0x47, 0x5f, 0x52, 0x45, 0x50, 0x4c, 0x59, 0x10, 0x03, 0x2a, 0x3d,
	0x0a, 0x08, 0x56, 0x6f, 0x74, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x10, 0x0a, 0x0c, 0x56, 0x4f,
	0x54, 0x45, 0x5f, 0x50, 0x52, 0x45, 0x50, 0x41, 0x52, 0x45, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b,
	0x56, 0x4f, 0x54, 0x45, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x49, 0x54, 0x10, 0x01, 0x12, 0x0e, 0x0a,
	0x0a, 0x56, 0x4f, 0x54, 0x45, 0x5f, 0x52, 0x45, 0x50, 0x4c, 0x59, 0x10, 0x02, 0x42, 0x09, 0x5a,
	0x07, 0x2e, 0x2e, 0x2f, 0x70, 0x62, 0x66, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pbft_proto_rawDescOnce sync.Once
	file_pbft_proto_rawDescData = file_pbft_proto_rawDesc
)

func file_pbft_proto_rawDescGZIP() []byte {
	file_pbft_proto_rawDescOnce.Do(func() {
		file_pbft_proto_rawDescData = protoimpl.X.CompressGZIP(file_pbft_proto_rawDescData)
	})
	return file_pbft_proto_rawDescData
}

var file_pbft_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_pbft_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_pbft_proto_goTypes = []interface{}{
	(Step)(0),          // 0: Step
	(PBFTMsgType)(0),   // 1: PBFTMsgType
	(VoteType)(0),      // 2: VoteType
	(*PBFTMsg)(nil),    // 3: PBFTMsg
	(*PrePrepare)(nil), // 4: PrePrepare
	(*Vote)(nil),       // 5: Vote
}
var file_pbft_proto_depIdxs = []int32{
	1, // 0: PBFTMsg.Type:type_name -> PBFTMsgType
	2, // 1: Vote.Type:type_name -> VoteType
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_pbft_proto_init() }
func file_pbft_proto_init() {
	if File_pbft_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pbft_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PBFTMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pbft_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PrePrepare); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pbft_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Vote); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pbft_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pbft_proto_goTypes,
		DependencyIndexes: file_pbft_proto_depIdxs,
		EnumInfos:         file_pbft_proto_enumTypes,
		MessageInfos:      file_pbft_proto_msgTypes,
	}.Build()
	File_pbft_proto = out.File
	file_pbft_proto_rawDesc = nil
	file_pbft_proto_goTypes = nil
	file_pbft_proto_depIdxs = nil
}
