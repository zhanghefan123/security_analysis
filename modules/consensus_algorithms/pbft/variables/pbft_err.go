package variables

import (
	"errors"
)

var (
	ErrAddVoteOnNilVoteset     = errors.New("add vote on member nil")
	ErrAddNilVote              = errors.New("add nil vote")
	ErrUnrecognizedVote        = errors.New("unrecognized vote")
	ErrAlreadyExistUserRequest = errors.New("already exist user request")
	ErrRequestHandleTimeOut    = errors.New("request handle time out")
	ErrUserDontExist           = errors.New("user dont exist")
	ErrWrongState              = errors.New("wrong state")
)
