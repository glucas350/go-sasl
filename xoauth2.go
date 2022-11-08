package sasl

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// The XOAUTH2 mechanism name.
const XOAuth2 = "XOAUTH2"

type XOAuth2Error struct {
	Status  string `json:"status"`
	Schemes string `json:"schemes"`
	Scope   string `json:"scope"`
}

type XOAuth2Options struct {
	Username     string
	AccessToken  string
	RefreshToken string
}

func OAuth2String(user, accessToken string) string {
	return "user=" + user + "\001auth=Bearer " + accessToken + "\001\001"
}

func XOAuth2String(user, accessToken string) string {
	s := OAuth2String(user, accessToken)
	if false {
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	return s
}

func (err *XOAuth2Error) Error() string {
	return fmt.Sprintf(XOAuth2+" authentication error (%v)", err.Status)
}

type xoauth2Client struct {
	XOAuth2Options
}

func (a *xoauth2Client) Start() (mech string, ir []byte, err error) {
	mech = XOAuth2
	ir = []byte(XOAuth2String(a.Username, a.AccessToken))
	return mech, ir, nil
}

func (a *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	authBearerErr := &XOAuth2Error{}
	if err := json.Unmarshal(challenge, authBearerErr); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", challenge, err)
	}
	return nil, fmt.Errorf("%s: %w", challenge, authBearerErr)
}

// An implementation of the OAUTHBEARER authentication mechanism, as
// described in RFC 7628.
func NewXOAuth2Client(opt *XOAuth2Options) *xoauth2Client {
	return &xoauth2Client{*opt}
}
