// Copyright 2026 DobbyVPN
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package outlinecaddy

import (
	"runtime/debug"

	"github.com/caddyserver/caddy/v2"
)

const outlineSourceVersion = "r3"

const (
	outlineCoreModule     = "golang.getoutline.org/tunnel-server"
	outlineCoreForkModule = "github.com/DobbyVPN/outliner-tunnel-server-fork"
)

type buildMetadata struct {
	buildModule   string
	buildVersion  string
	buildRevision string
	goVersion     string
	caddyVersion  string
	coreModule    string
	coreVersion   string
}

func readBuildMetadata() buildMetadata {
	metadata := buildMetadata{
		buildModule:   "unknown",
		buildVersion:  resolveBuildVersion(nil, caddy.CustomVersion, outlineSourceVersion),
		buildRevision: "unknown",
		goVersion:     "unknown",
		caddyVersion:  "unknown",
		coreModule:    outlineCoreModule,
		coreVersion:   "unknown",
	}
	metadata.caddyVersion, _ = caddy.Version()
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return metadata
	}
	if info.Main.Path != "" {
		metadata.buildModule = info.Main.Path
	}
	metadata.buildVersion = resolveBuildVersion(info, caddy.CustomVersion, outlineSourceVersion)
	if info.GoVersion != "" {
		metadata.goVersion = info.GoVersion
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && setting.Value != "" {
			metadata.buildRevision = setting.Value
		}
	}
	metadata.coreModule, metadata.coreVersion = effectiveCoreMetadata(info)
	return metadata
}

func effectiveCoreMetadata(info *debug.BuildInfo) (string, string) {
	modulePath := outlineCoreModule
	moduleVersion := "unknown"
	if info == nil {
		return modulePath, moduleVersion
	}
	for _, dependency := range info.Deps {
		if dependency.Path != outlineCoreModule && dependency.Path != outlineCoreForkModule {
			continue
		}
		modulePath = dependency.Path
		moduleVersion = dependency.Version
		if dependency.Replace != nil {
			if dependency.Replace.Path != "" {
				modulePath = dependency.Replace.Path
			}
			moduleVersion = dependency.Replace.Version
			if moduleVersion == "" {
				moduleVersion = "local"
			}
		}
		return modulePath, moduleVersion
	}
	return modulePath, moduleVersion
}

func resolveBuildVersion(info *debug.BuildInfo, customVersion, sourceVersion string) string {
	if customVersion != "" {
		return customVersion
	}
	if info != nil {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && setting.Value != "" {
				return setting.Value
			}
		}
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	if sourceVersion != "" {
		return sourceVersion
	}
	return "unknown"
}
