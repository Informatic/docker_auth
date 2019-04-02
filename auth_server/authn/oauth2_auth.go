/*
   Copyright 2016 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cesanta/glog"
)

type OAuth2Config struct {
	ClientId         string        `yaml:"client_id,omitempty"`
	ClientSecret     string        `yaml:"client_secret,omitempty"`
	ClientSecretFile string        `yaml:"client_secret_file,omitempty"`
	TokenDB          string        `yaml:"token_db,omitempty"`
	HTTPTimeout      time.Duration `yaml:"http_timeout,omitempty"`
	RevalidateAfter  time.Duration `yaml:"revalidate_after,omitempty"`
	AuthorizeUrl     string        `yaml:"authorize_url,omitempty"`
	AccessTokenUrl   string        `yaml:"access_token_url,omitempty"`
	ProfileUrl       string        `yaml:"profile_url,omitempty"`
	UsernameKey      string        `yaml:"username_key,omitempty"`
	RegistryUrl      string        `yaml:"registry_url,omitempty"`
	RedirectUrl      string        `yaml:"redirect_url,omitempty"`
}

type OAuth2 struct {
	config     *OAuth2Config
	db         TokenDB
	client     *http.Client
	tmpl       *template.Template
	tmplResult *template.Template
}

func NewOAuth2(c *OAuth2Config) (*OAuth2, error) {
	var db TokenDB
	var err error

	db, err = NewTokenDB(c.TokenDB)
	if err != nil {
		return nil, err
	}

	glog.Infof("OAuth2 auth token DB at %s", c.TokenDB)
	return &OAuth2{
		config:     c,
		db:         db,
		client:     &http.Client{Timeout: 10 * time.Second},
		tmpl:       template.Must(template.New("oauth2").Parse(string(MustAsset("data/oauth2_auth.tmpl")))),
		tmplResult: template.Must(template.New("oauth2_result").Parse(string(MustAsset("data/oauth2_auth_result.tmpl")))),
	}, nil
}

func (oa2 *OAuth2) doOAuth2Page(rw http.ResponseWriter, req *http.Request) {
	if err := oa2.tmpl.Execute(rw, struct {
		ClientId, AuthorizeUrl, RedirectUrl string
	}{
		ClientId:     oa2.config.ClientId,
		AuthorizeUrl: oa2.config.AuthorizeUrl,
		RedirectUrl:  oa2.config.RedirectUrl,
	}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

func (oa2 *OAuth2) doOAuth2ResultPage(rw http.ResponseWriter, username string, password string) {
	if err := oa2.tmplResult.Execute(rw, struct {
		Username, Password, RegistryUrl string
	}{
		Username:    username,
		Password:    password,
		RegistryUrl: oa2.config.RegistryUrl}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

func (oa2 *OAuth2) DoOAuth2(rw http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")

	if code != "" {
		oa2.doOAuth2CreateToken(rw, code)
	} else if req.Method == "GET" {
		oa2.doOAuth2Page(rw, req)
		return
	}
}

func (oa2 *OAuth2) doOAuth2CreateToken(rw http.ResponseWriter, code string) {
	data := url.Values{
		"code":          []string{string(code)},
		"client_id":     []string{oa2.config.ClientId},
		"client_secret": []string{oa2.config.ClientSecret},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{oa2.config.RedirectUrl},
	}

	req, err := http.NewRequest("POST", oa2.config.AccessTokenUrl+"?"+data.Encode(), bytes.NewBufferString(data.Encode()))
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error creating request to OAuth2 auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	req.Header.Add("Accept", "application/json")

	resp, err := oa2.client.Do(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error talking to OAuth2 auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	codeResp, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	glog.V(2).Infof("Code to token resp: %s %s", strings.Replace(string(codeResp), "\n", " ", -1), data.Encode())

	var c2t CodeToTokenResponse
	err = json.Unmarshal(codeResp, &c2t)
	if err != nil || c2t.Error != "" || c2t.ErrorDescription != "" {
		var et string
		if err != nil {
			et = err.Error()
		} else {
			et = fmt.Sprintf("%s: %s", c2t.Error, c2t.ErrorDescription)
		}
		http.Error(rw, fmt.Sprintf("Failed to get token: %s", et), http.StatusBadRequest)
		return
	}

	user, err := oa2.validateAccessToken(c2t.AccessToken)
	if err != nil {
		glog.Errorf("Newly-acquired token is invalid: %+v %s", c2t, err)
		http.Error(rw, "Newly-acquired token is invalid", http.StatusInternalServerError)
		return
	}

	glog.Infof("New OAuth2 auth token for %s", user)

	v := &TokenDBValue{
		TokenType:   c2t.TokenType,
		AccessToken: c2t.AccessToken,
		ValidUntil:  time.Now().Add(oa2.config.RevalidateAfter),
		// Labels:      map[string][]string{"teams": userTeams},
	}
	dp, err := oa2.db.StoreToken(user, v, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}

	oa2.doOAuth2ResultPage(rw, user, dp)
}

func (oa2 *OAuth2) validateAccessToken(token string) (user string, err error) {
	glog.Infof("OAuth2 Profile API: Fetching user info")
	req, err := http.NewRequest("GET", oa2.config.ProfileUrl, nil)
	if err != nil {
		err = fmt.Errorf("could not create request to get information for token %s: %s", token, err)
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Accept", "application/json")

	resp, err := oa2.client.Do(req)
	if err != nil {
		err = fmt.Errorf("could not verify token %s: %s", token, err)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	ti := map[string]interface{}{}
	err = json.Unmarshal(body, &ti)
	if err != nil {
		err = fmt.Errorf("could not unmarshal token user info %q: %s", string(body), err)
		return
	}
	glog.V(2).Infof("Token user info: %+v", strings.Replace(string(body), "\n", " ", -1))

	return ti[oa2.config.UsernameKey].(string), nil
}

func (oa2 *OAuth2) validateServerToken(user string) (*TokenDBValue, error) {
	v, err := oa2.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return nil, err
	}

	texp := v.ValidUntil.Sub(time.Now())
	glog.V(3).Infof("Existing OAuth2 auth token for <%s> expires after: <%d> sec", user, int(texp.Seconds()))

	glog.V(1).Infof("Token has expired. I will revalidate the access token.")
	glog.V(3).Infof("Old token is: %+v", v)
	tokenUser, err := oa2.validateAccessToken(v.AccessToken)
	if err != nil {
		glog.Warningf("Token for %q failed validation: %s", user, err)
		return nil, fmt.Errorf("server token invalid: %s", err)
	}
	if tokenUser != user {
		glog.Errorf("token for wrong user: expected %s, found %s", user, tokenUser)
		return nil, fmt.Errorf("found token for wrong user")
	}

	// Update revalidation timestamp
	v.ValidUntil = time.Now().Add(oa2.config.RevalidateAfter)
	glog.V(3).Infof("New token is: %+v", v)

	// Update token
	_, err = oa2.db.StoreToken(user, v, false)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		return nil, fmt.Errorf("Unable to store renewed token expiry time: %s", err)
	}
	glog.V(2).Infof("Successfully revalidated token")

	texp = v.ValidUntil.Sub(time.Now())
	glog.V(3).Infof("Re-validated OAuth2 auth token for %s. Next revalidation in %dsec.", user, int64(texp.Seconds()))
	return v, nil
}

func (oa2 *OAuth2) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	err := oa2.db.ValidateToken(user, password)
	if err == ExpiredToken {
		_, err = oa2.validateServerToken(user)
		if err != nil {
			return false, nil, err
		}
	} else if err != nil {
		return false, nil, err
	}

	v, err := oa2.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return false, nil, err
	}

	return true, v.Labels, nil
}

func (oa2 *OAuth2) Stop() {
	oa2.db.Close()
	glog.Info("Token DB closed")
}

func (oa2 *OAuth2) Name() string {
	return "OAuth2"
}
