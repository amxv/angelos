package mail

// XOAUTH2 is Google's SASL mechanism; OAUTHBEARER is a different wire format.
// The IMAP/SMTP libraries perform the single required base64 encoding.
type xoauth2Client struct {
	username   string
	token      string
	started    bool
	challenged bool
}

func (c *xoauth2Client) Start() (string, []byte, error) {
	if c.started || !bareAddress(c.username) || !validGoogleAccessToken(c.token) {
		return "", nil, ErrUnavailable
	}
	c.started = true
	return "XOAUTH2", []byte("user=" + c.username + "\x01auth=Bearer " + c.token + "\x01\x01"), nil
}

func (c *xoauth2Client) Next(_ []byte) ([]byte, error) {
	if !c.started || c.challenged {
		return nil, ErrUnavailable
	}
	// Every Gmail continuation after the initial response indicates a failure.
	// Acknowledge once without echoing/parsing provider data, then await the
	// terminal reply. NON-NIL empty bytes are essential: go-smtp interprets nil
	// as successful exchange completion without reading the final failure.
	c.challenged = true
	return []byte{}, nil
}
