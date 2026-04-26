package errors

import stderrors "errors"

var (
	ErrNotFound     = stderrors.New("not found")
	ErrUnauthorized = stderrors.New("unauthorized")
	ErrForbidden    = stderrors.New("forbidden")
	ErrTrustDenied  = stderrors.New("trust score too low")
	ErrTokenReuse   = stderrors.New("token reuse detected")
	ErrTokenExpired  = stderrors.New("token expired")
	ErrInvalidPKCE  = stderrors.New("invalid PKCE code verifier")
)
