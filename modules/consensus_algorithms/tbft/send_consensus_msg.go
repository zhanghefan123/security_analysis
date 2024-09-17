package tbft

import (
	"github.com/gogo/protobuf/proto"
	"zhanghefan123/security/common/msgbus"
	tbftpb "zhanghefan123/security/protobuf/pb-go/consensus/tbft"
	netpb "zhanghefan123/security/protobuf/pb-go/net"
)

//
// sendConsensusMsg
// @Description: send consensus msg,If to is an empty string, send to all validators
// @receiver consensus
// @param msg
// @param to
//
func (consensus *ConsensusTBFTImpl) sendConsensusMsg(msg proto.Message, to string) {
	if msg == nil {
		return
	}

	var validators []string
	if to != "" {
		validators = append(validators, to)
	} else {
		validators = append(validators, consensus.validatorSet.Validators...)
	}

	consensus.logger.Infof("%s ready send consensus message to %v ", consensus.Id, validators)
	for _, v := range validators {
		// The recipient is yourself
		if v == consensus.Id {
			continue
		}
		go func(validator string) {
			netMsg := &netpb.NetMsg{
				Payload: mustMarshal(msg),
				Type:    netpb.NetMsg_CONSENSUS_MSG,
				To:      validator,
			}
			consensus.logger.Infof("%s send consensus message to %s succeeded", consensus.Id, validator)
			consensus.msgbus.Publish(msgbus.SendConsensusMsg, netMsg)
		}(v)
	}
}

// send consensus proposal
func (consensus *ConsensusTBFTImpl) sendConsensusProposal(proposal *TBFTProposal, to string) {
	if proposal == nil || proposal.Bytes == nil {
		return
	}
	msg := createProposalTBFTMsg(proposal)

	consensus.logger.Infof("%s send consensus proposal", consensus.Id)
	consensus.sendConsensusMsg(msg, to)
}

// send consensus vote
// prevote or precommit
func (consensus *ConsensusTBFTImpl) sendConsensusVote(vote *tbftpb.Vote, to string) {
	if vote == nil {
		return
	}

	var msg *tbftpb.TBFTMsg
	switch vote.Type {
	case tbftpb.VoteType_VOTE_PREVOTE:
		msg = createPrevoteTBFTMsg(vote)
	case tbftpb.VoteType_VOTE_PRECOMMIT:
		msg = createPrecommitTBFTMsg(vote)
	}

	consensus.logger.Infof("%s send consensus %s", consensus.Id, vote.String())
	consensus.sendConsensusMsg(msg, to)
}
