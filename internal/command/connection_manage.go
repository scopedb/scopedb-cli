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

package command

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/scopedb/scopedb-cli/internal/filelock"
	"github.com/spf13/cobra"
)

func (a *app) connectionCatalog(cmd *cobra.Command) (config.Paths, config.Config, error) {
	paths, err := config.ResolvePaths()
	if err != nil {
		return paths, config.Config{}, err
	}
	cfg, err := config.Read(paths)
	if err != nil {
		return paths, cfg, err
	}
	selected := strings.TrimSpace(a.getenv("SCOPEDB_CONNECTION"))
	if cmd.Root().PersistentFlags().Changed("connection") {
		selected = a.connectionFlag
	}
	a.explicitConnection = selected != ""
	if selected != "" {
		if err := config.ValidateConnectionName(selected); err != nil {
			return paths, cfg, usageError(err.Error())
		}
		if _, ok := cfg.Connections[selected]; !ok {
			return paths, cfg, fmt.Errorf("%w: %q", config.ErrUnknownConnection, selected)
		}
	} else if a.getenv("SCOPEDB_ENDPOINT") == "" && a.getenv("SCOPEDB_API_KEY") == "" {
		selected = cfg.DefaultConnection
	}
	cfg.ConnectionName = selected
	return paths, cfg, nil
}

func (a *app) newConnectionAddCommand() *cobra.Command {
	var authType, endpoint, keyEnv, format string
	var keyStdin, insecure bool
	command := &cobra.Command{Use: "add <name>", Short: "Save an OAuth or API key connection", Args: exactArgs(1),
		Long: "Save an OAuth or API key connection. OAuth discovers the data service endpoint for the selected workspace.\n" +
			"API key connections save an endpoint and use the workspace authorized by their key.\n" +
			"Multiple connections and workspaces can use the same endpoint.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			if err := config.ValidateConnectionName(args[0]); err != nil {
				return usageError(err.Error())
			}
			if authType != config.AuthOAuth && authType != config.AuthAPIKey {
				return usageError("--auth-type must be oauth or api_key")
			}
			if authType == config.AuthOAuth && (endpoint != "" || keyEnv != "" || keyStdin || insecure) {
				return usageError("OAuth connections do not accept API key settings; run auth login after adding the connection")
			}
			if authType == config.AuthAPIKey {
				if keyStdin == (keyEnv != "") {
					return usageError("provide exactly one of --api-key-stdin or --api-key-env")
				}
				var err error
				endpoint, err = config.NormalizeEndpoint(endpoint)
				if err != nil {
					return usageError("--endpoint must be an absolute HTTP(S) URL without credentials, query, or fragment")
				}
				if keyEnv != "" && !validEnvName(keyEnv) {
					return usageError("--api-key-env requires an environment variable name")
				}
				if insecure && !keyStdin {
					return usageError("--insecure-storage requires --api-key-stdin")
				}
			}
			key := ""
			if keyStdin {
				value, err := readInput(cmd.Context(), func() (string, error) {
					data, err := io.ReadAll(io.LimitReader(a.in, 65537))
					return string(data), err
				})
				if err != nil {
					return err
				}
				key = strings.TrimSpace(value)
				if key == "" || len(key) > 65536 || strings.ContainsAny(key, "\r\n\t ") {
					return usageError("stdin must contain one non-empty API key")
				}
			}
			paths, err := config.ResolvePaths()
			if err != nil {
				return err
			}
			// Claim a legacy login as default before adding a second configuration.
			saved, err := config.Read(paths)
			if err != nil {
				return err
			}
			if len(saved.Connections) == 0 {
				initial, err := config.Load(paths, config.Overrides{})
				if err != nil {
					return err
				}
				if _, err := a.newRuntime(cmd.Context(), paths, initial); err != nil {
					return err
				}
			}
			lock, err := filelock.Acquire(cmd.Context(), paths.LockFile)
			if err != nil {
				return err
			}
			defer func() { _ = lock.Close() }()
			cfg, err := config.Load(paths, config.Overrides{Connection: args[0], AllowCreate: true, ControlURL: a.controlURLFlag, ConsoleURL: a.consoleURLFlag})
			if err != nil {
				return err
			}
			if cfg.ConnectionExists {
				return usageError("connection already exists; remove it before adding a replacement")
			}
			connection := cfg.SelectedConnection
			if authType == config.AuthAPIKey {
				connection = config.Connection{AuthType: authType, Endpoint: endpoint, APIKeyEnv: keyEnv}
			}
			cfg.SelectedConnection, cfg.ConnectionExists = connection, true
			runtime, err := a.newRuntime(cmd.Context(), paths, cfg)
			if err != nil {
				return err
			}
			runtime.credentials.InsecureStorage = insecure
			if keyStdin {
				if err := runtime.credentials.Replace(endpoint, credential.State{APIKey: key}); err != nil {
					return err
				}
			}
			if err := config.SaveConnection(paths, args[0], connection, true); err != nil {
				if keyStdin {
					err = errors.Join(err, runtime.credentials.Delete(endpoint))
				}
				return err
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, connectionUseResult{Name: args[0], Changed: true})
			}
			_, err = fmt.Fprintf(a.out, "Added connection %s.\n", args[0])
			return err
		},
	}
	command.Flags().StringVar(&authType, "auth-type", config.AuthOAuth, "authentication type: oauth or api_key")
	command.Flags().StringVar(&endpoint, "endpoint", "", "data service URL for an API key connection")
	command.Flags().BoolVar(&keyStdin, "api-key-stdin", false, "read an API key from stdin and save it in the credential store")
	command.Flags().StringVar(&keyEnv, "api-key-env", "", "read the API key from this environment variable at runtime")
	command.Flags().BoolVar(&insecure, "insecure-storage", false, "store the supplied API key unencrypted")
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	return command
}

func validEnvName(name string) bool {
	for i, r := range name {
		valid := r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9'
		if !valid {
			return false
		}
	}
	return name != ""
}

func (a *app) newConnectionRemoveCommand() *cobra.Command {
	var yes bool
	var format string
	command := &cobra.Command{Use: "remove <name>", Short: "Remove a connection and its local credentials; revoke its OAuth login", Args: exactArgs(1), ValidArgsFunction: a.completeConnections,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			paths, cfg, err := a.connectionCatalog(cmd)
			if err != nil {
				return err
			}
			if _, ok := cfg.Connections[args[0]]; !ok {
				return fmt.Errorf("%w: %q", config.ErrUnknownConnection, args[0])
			}
			if !yes {
				if !a.isInputTerminal() {
					return usageError("connection remove requires --yes when not interactive")
				}
				answer, err := a.readLine(cmd.Context(), "Remove connection "+args[0]+" and end its OAuth login, if any? [y/N] ")
				if err != nil {
					return err
				}
				if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
					return usageError("connection removal cancelled")
				}
			}
			lock, err := filelock.Acquire(cmd.Context(), paths.LockFile)
			if err != nil {
				return err
			}
			defer func() { _ = lock.Close() }()
			cfg, err = config.Read(paths)
			if err != nil {
				return err
			}
			connection, ok := cfg.Connections[args[0]]
			if !ok {
				return fmt.Errorf("%w: %q", config.ErrUnknownConnection, args[0])
			}
			cfg.ConnectionName, cfg.SelectedConnection, cfg.ConnectionExists = args[0], connection, true
			if connection.AuthType == config.AuthOAuth {
				cfg.ControlURL, cfg.ConsoleURL = connection.ControlURL, connection.ConsoleURL
			}
			runtime, err := a.newRuntime(cmd.Context(), paths, cfg)
			if err != nil {
				return err
			}
			a.resolvedConnection = args[0]
			origin := connection.CredentialOrigin()
			if connection.AuthType == config.AuthOAuth {
				state, err := runtime.credentials.Load(origin)
				if err != nil && !errors.Is(err, credential.ErrNotFound) {
					return err
				}
				if err == nil {
					token := state.RefreshToken
					if token == "" {
						token = state.AccessToken
					}
					ctx, cancel := timeoutContext(cmd.Context(), 15*time.Second)
					revokeErr := runtime.RevokeToken(ctx, token)
					cancel()
					if revokeErr != nil {
						return clierror.WithHint(clierror.Wrap(clierror.ExitCode(NormalizeError(revokeErr)), "connection retained because its login could not be revoked", revokeErr), "retry connection remove after restoring access to the service")
					}
				}
			}
			if err := runtime.credentials.Delete(origin); err != nil && !errors.Is(err, credential.ErrNotFound) {
				return err
			}
			delete(cfg.Connections, args[0])
			if cfg.DefaultConnection == args[0] {
				cfg.DefaultConnection = ""
			}
			if err := config.Save(paths, cfg); err != nil {
				return err
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, connectionUseResult{Name: args[0], Changed: true})
			}
			_, err = fmt.Fprintf(a.out, "Removed connection %s.\n", args[0])
			return err
		},
	}
	command.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation")
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	return command
}
