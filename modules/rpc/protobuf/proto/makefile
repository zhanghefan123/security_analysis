all: dev gen

gen:
	protoc --go_out=plugins=grpc:../pb-go authentication.proto
	protoc --go_out=plugins=grpc:../pb-go message.proto

dev:
	go install github.com/golang/protobuf/protoc-gen-go