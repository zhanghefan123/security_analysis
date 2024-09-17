package message

import pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"

// NewPrePrepare 创建新的 prePrepare 消息
func NewPrePrepare(userId, accessId string) *pbftPb.PrePrepare {
	return &pbftPb.PrePrepare{
		UserId:   userId,
		AccessId: accessId,
	}
}
