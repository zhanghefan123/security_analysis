# 1. 问题1

- 当我们进行 require 的时候，下载的并不是我们所指定的版本。 
- 检查依赖图 go mod graph | grep golang.org/x/crypto
- 检查发现是 protobuf -> net v0.27.0 -> crypto v0.24.0

# 2. 问题2

- 按照官方文档进行操作的使用 go1.19 版本，会导致 quic-go 版本报错。
- go 1.17 版本不支持 workspace, 不方便进行同时多模块的编写。
- 所以推荐使用 go1.18 版本。

# 3. 问题3

- 由于 libp2p 引用了 libp2p-pubsub 而这个对 protocol v2.3.0 存在依赖关系。而 protocol v2.3.0 之中使用了官方的 chainmaker.org/chainmaker/pb-go
- 和本地所使用的 pb-go 相冲突，导致了重复定义的问题的出现。