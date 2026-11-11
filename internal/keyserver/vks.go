package keyserver

import (
	"context"
	"encoding/json"
	"fmt"
)

// Upload publishes an armored public key via the VKS upload API
// (POST /vks/v1/upload). It returns the opaque token the server answers
// with; keys.openpgp.org hides user IDs until they are verified through
// RequestVerify.
func (c *Client) Upload(ctx context.Context, armoredKey string) (string, error) {
	body, err := json.Marshal(struct {
		Keymaterial string `json:"keymaterial"`
	}{armoredKey})
	if err != nil {
		return "", err
	}
	data, err := c.fetch.Post(ctx, c.base.JoinPath("vks", "v1", "upload").String(), "application/json", body)
	if err != nil {
		return "", err
	}
	var reply struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return "", fmt.Errorf("keyserver answered something unexpected: %w", err)
	}
	if reply.Token == "" {
		return "", fmt.Errorf("keyserver did not answer with a token")
	}
	return reply.Token, nil
}

// RequestVerify asks the keyserver to email a verification link for token to
// each address (they must be user IDs of the uploaded key).
func (c *Client) RequestVerify(ctx context.Context, token string, addresses []string) error {
	body, err := json.Marshal(struct {
		Token     string   `json:"token"`
		Addresses []string `json:"addresses"`
	}{token, addresses})
	if err != nil {
		return err
	}
	_, err = c.fetch.Post(ctx, c.base.JoinPath("vks", "v1", "request-verify").String(), "application/json", body)
	return err
}
