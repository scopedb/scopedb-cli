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

package version

import "runtime/debug"

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// Info contains build metadata injected by release builds.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Current returns the CLI build metadata.
func Current() Info {
	info := Info{Version: version, Commit: commit, Date: date}
	if info.Version != "dev" {
		return info
	}

	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	if build.Main.Version != "" && build.Main.Version != "(devel)" {
		info.Version = build.Main.Version
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == "unknown" {
				info.Commit = setting.Value
			}
		case "vcs.time":
			if info.Date == "unknown" {
				info.Date = setting.Value
			}
		}
	}
	return info
}
