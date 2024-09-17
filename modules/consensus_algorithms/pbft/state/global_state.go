package state

import (
	"zhanghefan123/security/modules/consensus_algorithms/pbft/validator"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/variables"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/vote"
	pb "zhanghefan123/security/modules/rpc/protobuf/pb-go"
	"zhanghefan123/security/protocol"
)

// GlobalState 共识状态
type GlobalState struct {
	Logger                protocol.Logger
	LocalPeerId           string                                  // 当前卫星的 peerId
	ValidatorSet          *validator.ValidatorSet                 // 所有的验证者集合
	CurrentUsers          map[string]interface{}                  // 当前的所有用户
	UserVoteSets          map[string]*vote.UserVoteSet            // 每个用户在各个阶段的投票集合
	UserStates            map[string]*UserState                   // 每个用户的状态
	AuthenticationResults map[string]chan pb.AuthenticationResult // 这个是给用户响应的结果
}

// NewConsensusState 新的共识状态
func NewConsensusState(logger protocol.Logger, localPeerId string, validatorSet *validator.ValidatorSet) *GlobalState {
	return &GlobalState{
		Logger:                logger,
		LocalPeerId:           localPeerId,
		ValidatorSet:          validatorSet,
		CurrentUsers:          make(map[string]interface{}),
		UserVoteSets:          make(map[string]*vote.UserVoteSet),
		UserStates:            make(map[string]*UserState),
		AuthenticationResults: make(map[string]chan pb.AuthenticationResult),
	}
}

// AddUserForAuthentication 添加等待认证的用户
func (gs *GlobalState) AddUserForAuthentication(userId string, resultChan chan pb.AuthenticationResult) error {
	// 判断是否已经存在了等待认证的用户
	if _, ok := gs.CurrentUsers[userId]; ok {
		gs.Logger.Errorf("user authentication already exist")
		return variables.ErrAlreadyExistUserRequest
	}
	gs.CurrentUsers[userId] = struct{}{}
	gs.UserVoteSets[userId] = vote.NewUserVoteSet(gs.Logger, gs.ValidatorSet) // 设置投票集
	gs.UserStates[userId] = NewUserState(userId)                              // 新的状态
	gs.AuthenticationResults[userId] = resultChan                             // 创建投票结果
	return nil
}
