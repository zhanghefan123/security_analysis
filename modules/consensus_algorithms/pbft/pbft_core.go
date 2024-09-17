package pbft

import (
	"context"
	"sync"
	"zhanghefan123/security/common/msgbus"
	consensusutils "zhanghefan123/security/consensus-utils"
	"zhanghefan123/security/modules/consensus_algorithms"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/handler"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/message"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/state"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/validator"
	"zhanghefan123/security/modules/request_pool"
	"zhanghefan123/security/modules/utils"
	"zhanghefan123/security/protobuf/pb-go/net"
	"zhanghefan123/security/protocol"
)

// ConsensusPbftImpl pbft 共识的实现
type ConsensusPbftImpl struct {
	sync.RWMutex                                   // 读写锁
	Ctx             context.Context                // 上下文
	Logger          protocol.Logger                // 日志记录器
	LocalPeerId     string                         // 本地节点 peerId
	ChainConfig     *protocol.ChainConf            // 链配置
	ValidatorSet    *validator.ValidatorSet        // 验证者集合
	ConsensusState  *state.GlobalState             // 存储了共识状态，包括对于每个请求的投票集合
	LegalUsers      *map[string]interface{}        // 记录合法的用户，为了方便查找这里使用的是 map
	MsgBus          msgbus.MessageBus              // 消息总线
	InternalMsgChan chan *message.ConsensusMessage // 内部消息队列
	ExternalMsgChan chan *message.ConsensusMessage // 外部消息队列
	RequestPool     *request_pool.RequestPool      // 请求池
}

// New 通过 ConsensusImplConfig 创建新的 ConsensusPbftImpl 实例
func New(config *consensusutils.ConsensusImplConfig) (*ConsensusPbftImpl, error) {
	// 从 localconf 之中获取 validator
	validators := utils.GetValidatorsFromLocalConfig()

	// 设置 validatorSet
	validatorSet := validator.NewValidatorSet(config.Logger, validators)

	// 创建 pbft 实例
	pbftImpl := &ConsensusPbftImpl{
		Logger:          config.Logger,
		LocalPeerId:     config.NodeId,
		ChainConfig:     &config.ChainConf,
		ValidatorSet:    validatorSet,
		ConsensusState:  state.NewConsensusState(config.Logger, config.NodeId, validatorSet),
		MsgBus:          config.MsgBus,
		InternalMsgChan: make(chan *message.ConsensusMessage),
		ExternalMsgChan: make(chan *message.ConsensusMessage),
		RequestPool:     config.RequestPool,
	}

	// 将创建的结果进行返回
	return pbftImpl, nil
}

// OnMessage 收到消息时候的处理行为
func (pbftImpl *ConsensusPbftImpl) OnMessage(msg *msgbus.Message) {
	switch msg.Topic {
	// 仅仅进行了 RecvConsensusMsg 消息的订阅
	case msgbus.RecvConsensusMsg:
		// 将 payload 转换为 NetMsg
		if msg, ok := msg.Payload.(net.NetMsg); ok {
			// 将 netMsg 之中的内容转换为 consensusMsg
			consensusMsg := message.CreateConsensusMsgFromBytes(msg.Payload)

			// 输出收到了消息
			pbftImpl.Logger.Infof("OnMessage receive message")

			// 向外部 channel 发送消息
			pbftImpl.ExternalMsgChan <- consensusMsg
		}
	default:
		panic("unhandled default case")
	}
}

// OnQuit -> 这是 subscriber 的方法
func (pbftImpl *ConsensusPbftImpl) OnQuit() {
	pbftImpl.Logger.Infof("tbft quit")
}

// RegisterMsgBusTopics 记录消息总线的主题
func (pbftImpl *ConsensusPbftImpl) RegisterMsgBusTopics() {
	pbftImpl.Logger.Infof("register pbft needed topics")
	for _, topic := range consensus_algorithms.PbftMsgBusTopics {
		pbftImpl.MsgBus.Register(topic, pbftImpl)
	}
}

// Start 启动方法
func (pbftImpl *ConsensusPbftImpl) Start() error {
	pbftImpl.RegisterMsgBusTopics()
	go handler.Handle(pbftImpl)
	return nil
}

// Stop 停止方法
func (pbftImpl *ConsensusPbftImpl) Stop() error {
	return nil
}
