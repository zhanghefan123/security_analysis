// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: syscontract/dpos_slashing.proto

package syscontract

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Methods of DPoS Slashing contract
type DPoSSlashingFunction int32

const (
	// Punish for Slashing
	DPoSSlashingFunction_PUNISH DPoSSlashingFunction = 0
	// Set Slashing per block
	DPoSSlashingFunction_SET_SLASHING_PER_BLOCK DPoSSlashingFunction = 2
	// Get Slashing per Block
	DPoSSlashingFunction_GET_SLASHING_PER_BLOCK DPoSSlashingFunction = 3
)

var DPoSSlashingFunction_name = map[int32]string{
	0: "PUNISH",
	2: "SET_SLASHING_PER_BLOCK",
	3: "GET_SLASHING_PER_BLOCK",
}

var DPoSSlashingFunction_value = map[string]int32{
	"PUNISH":                 0,
	"SET_SLASHING_PER_BLOCK": 2,
	"GET_SLASHING_PER_BLOCK": 3,
}

func (x DPoSSlashingFunction) String() string {
	return proto.EnumName(DPoSSlashingFunction_name, int32(x))
}

func (DPoSSlashingFunction) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_db50c850de09cdec, []int{0}
}

func init() {
	proto.RegisterEnum("syscontract.DPoSSlashingFunction", DPoSSlashingFunction_name, DPoSSlashingFunction_value)
}

func init() { proto.RegisterFile("syscontract/dpos_slashing.proto", fileDescriptor_db50c850de09cdec) }

var fileDescriptor_db50c850de09cdec = []byte{
	// 202 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x2f, 0xae, 0x2c, 0x4e,
	0xce, 0xcf, 0x2b, 0x29, 0x4a, 0x4c, 0x2e, 0xd1, 0x4f, 0x29, 0xc8, 0x2f, 0x8e, 0x2f, 0xce, 0x49,
	0x2c, 0xce, 0xc8, 0xcc, 0x4b, 0xd7, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x46, 0x52, 0xa0,
	0x15, 0xc5, 0x25, 0xe2, 0x12, 0x90, 0x1f, 0x1c, 0x0c, 0x55, 0xe2, 0x56, 0x9a, 0x97, 0x5c, 0x92,
	0x99, 0x9f, 0x27, 0xc4, 0xc5, 0xc5, 0x16, 0x10, 0xea, 0xe7, 0x19, 0xec, 0x21, 0xc0, 0x20, 0x24,
	0xc5, 0x25, 0x16, 0xec, 0x1a, 0x12, 0x1f, 0xec, 0xe3, 0x18, 0xec, 0xe1, 0xe9, 0xe7, 0x1e, 0x1f,
	0xe0, 0x1a, 0x14, 0xef, 0xe4, 0xe3, 0xef, 0xec, 0x2d, 0xc0, 0x04, 0x92, 0x73, 0xc7, 0x2e, 0xc7,
	0xec, 0x94, 0x7e, 0xe2, 0x91, 0x1c, 0xe3, 0x85, 0x47, 0x72, 0x8c, 0x0f, 0x1e, 0xc9, 0x31, 0x4e,
	0x78, 0x2c, 0xc7, 0x70, 0xe1, 0xb1, 0x1c, 0xc3, 0x8d, 0xc7, 0x72, 0x0c, 0x5c, 0xb2, 0xf9, 0x45,
	0xe9, 0x7a, 0xc9, 0x19, 0x89, 0x99, 0x79, 0xb9, 0x89, 0xd9, 0xa9, 0x45, 0x7a, 0x05, 0x49, 0x7a,
	0x48, 0x8e, 0x8a, 0x42, 0x96, 0xca, 0x2f, 0x4a, 0xd7, 0x47, 0x70, 0xf5, 0x0b, 0x92, 0x74, 0xd3,
	0xf3, 0xf5, 0xcb, 0x8c, 0xf4, 0x91, 0xd4, 0x27, 0xb1, 0x81, 0x3d, 0x66, 0x0c, 0x08, 0x00, 0x00,
	0xff, 0xff, 0xbb, 0x7a, 0xff, 0x92, 0xfb, 0x00, 0x00, 0x00,
}
