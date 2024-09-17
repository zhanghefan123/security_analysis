package state

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/variables"
)

// UserState 状态
type UserState struct {
	UserId string
	Step   pbftPb.Step
}

// NewUserState 创建用户状态
func NewUserState(userId string) *UserState {
	return &UserState{
		UserId: userId,
		Step:   pbftPb.Step_PRE_PREPARE,
	}
}

// EnterPrepareStage 进入 Prepare 阶段
func (us *UserState) EnterPrepareStage() error {
	if us.Step == pbftPb.Step_PRE_PREPARE {
		us.Step = pbftPb.Step_PREPARE
	}
	return variables.ErrWrongState
}

// EnterCommitStage 进入 Commit 阶段
func (us *UserState) EnterCommitStage() error {
	if us.Step == pbftPb.Step_PREPARE {
		us.Step = pbftPb.Step_COMMIT
	}
	return variables.ErrWrongState
}

// EnterReplyStage 进入响应阶段
func (us *UserState) EnterReplyStage() error {
	if us.Step == pbftPb.Step_COMMIT {
		us.Step = pbftPb.Step_REPLY
	}
	return variables.ErrWrongState
}

// EnterCompleteStage 进入结束阶段
func (us *UserState) EnterCompleteStage() error {
	if us.Step == pbftPb.Step_REPLY {
		us.Step = pbftPb.Step_COMPLETE
	}
	return variables.ErrWrongState
}
