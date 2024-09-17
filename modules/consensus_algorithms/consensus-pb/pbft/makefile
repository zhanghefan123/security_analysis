all: dev gen

gen:
	protoc --go_out=../pbft pbft.proto

dev:
	go install github.com/golang/protobuf/protoc-gen-go