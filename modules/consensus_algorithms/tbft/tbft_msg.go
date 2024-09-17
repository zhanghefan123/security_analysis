package tbft

import "zhanghefan123/security/protobuf/pb-go/consensus/tbft"

type TBFTProposal struct {
	PbMsg *tbft.Proposal
	Bytes []byte // byte format *tbftpb.Proposal
}

// NewTBFTProposal 创建新的 tbft proposal 实例
func NewTBFTProposal(proposalPb *tbft.Proposal, marshal bool) *TBFTProposal {
	tbftProposal := &TBFTProposal{
		PbMsg: proposalPb,
	}
	if marshal {
		tbftProposal.Bytes = mustMarshal(proposalPb)
	}
	return tbftProposal
}

// Marshal 直接覆盖旧的 bytes
func (p *TBFTProposal) Marshal() {
	p.Bytes = mustMarshal(p.PbMsg)
}
