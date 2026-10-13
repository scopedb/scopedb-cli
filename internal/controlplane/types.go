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

// User is the account behind a credential. The CLI reads it from /api/user instead of the
// browser-session resource, which an OAuth access token cannot use.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Status       string `json:"status"`
	Introduction string `json:"introduction"`
	CreatedAt    string `json:"created_at"`
}

// Workspace summarises an owned workspace. Workspaces scheduled for deletion stay in the list and
// keep their routes unavailable until they are restored.
type Workspace struct {
	ID                     string     `json:"id"`
	DisplayName            *string    `json:"display_name"`
	Provider               string     `json:"provider"`
	Region                 string     `json:"region"`
	ProvisioningStatus     string     `json:"provisioning_status"`
	ScheduledForDeletionAt *time.Time `json:"scheduled_for_deletion_at"`
}

func (w Workspace) Name() string {
	if w.DisplayName != nil && *w.DisplayName != "" {
		return *w.DisplayName
	}
	return w.ID
}

// ScheduledForDeletion reports whether the workspace is on its way out, which makes every
// workspace-scoped route answer 404 until it is restored.
func (w Workspace) ScheduledForDeletion() bool {
	return w.ScheduledForDeletionAt != nil
}

type WorkspacesResponse struct {
	Workspaces []Workspace `json:"workspaces"`
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
	UpdatedAt *time.Time `json:"updated_at"`
}

// CreateWorkspaceRequest is the Console and CLI request for a new workspace.
type CreateWorkspaceRequest struct {
	DisplayName string `json:"display_name"`
	Provider    string `json:"provider"`
	Region      string `json:"region"`
}

// CreateWorkspaceResponse carries the workspace that was created. The token is empty for an OAuth
// credential, which is never rotated to change workspace.
type CreateWorkspaceResponse struct {
	Token       string `json:"token"`
	WorkspaceID string `json:"workspace_id"`
}

// SignupConfig lists the placements a new workspace can be created in.
type SignupConfig struct {
	DefaultPlacement *Placement  `json:"default_placement"`
	Placements       []Placement `json:"placements"`
}

type TokenExchangeResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int       `json:"expires_in"`
	ExpiresAt   time.Time `json:"expires_at"`
}
