// Copyright 2026 ScopeDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

import "time"

type LoginBeginResponse struct {
	LoginChallenge string `json:"login_challenge"`
}

type LoginResponse struct {
	Token       string `json:"token"`
	WorkspaceID string `json:"workspace_id"`
}

type Session struct {
	User               User        `json:"user"`
	Workspaces         []Workspace `json:"workspaces"`
	CurrentWorkspaceID string      `json:"current_workspace_id"`
}

type User struct {
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

type Workspace struct {
	ID          string  `json:"id"`
	DisplayName *string `json:"display_name"`
	Role        string  `json:"role"`
}

func (w Workspace) Name() string {
	if w.DisplayName != nil && *w.DisplayName != "" {
		return *w.DisplayName
	}
	return w.ID
}

type WorkspaceDetails struct {
	Workspace    Workspace    `json:"workspace"`
	Connection   Connection   `json:"connection"`
	Placement    Placement    `json:"placement"`
	Provisioning Provisioning `json:"provisioning"`
}

type Connection struct {
	APIBaseURL string `json:"api_base_url"`
	AuthScheme string `json:"auth_scheme"`
}

type Placement struct {
	Provider string `json:"provider"`
	Region   string `json:"region"`
}

type Provisioning struct {
	Status    string     `json:"status"`
	Code      *string    `json:"code"`
	Reason    *string    `json:"reason"`
	Retryable *bool      `json:"retryable"`
	Action    *string    `json:"action"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type TokenExchangeResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int       `json:"expires_in"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name"`
	Tags      []string   `json:"tags"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type APIKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Tags      []string   `json:"tags"`
	Status    string     `json:"status"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Key       string     `json:"key,omitempty"`
}
