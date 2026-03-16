package scaffold

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Create(name string) error {
	title := toTitle(name)

	files := map[string]string{
		"mirrorstack.yaml":                mirrorstackYAML(name, title),
		"MIRRORSTACK.md":                  mirrorstackMD(name, title),
		".gitignore":                      gitignore(),
		"sql/0000_initial.up.sql":         initialUpSQL(),
		"sql/0000_initial.down.sql":       initialDownSQL(),
		"api/go.mod":                      goMod(name),
		"api/module.go":                   moduleGo(name, title),
		"api/cmd/main.go":                 cmdMainGo(name),
		"api/handler/public.go":           handlerPublicGo(name),
		"api/handler/admin.go":            handlerAdminGo(name),
		"api/service/" + name + ".go":     serviceGo(name),
		"api/db/sqlc.yaml":                sqlcYAML(name),
		"api/db/queries/" + name + ".sql": queriesSQL(name),
		"web/package.json":                webPackageJSON(name),
		"web/platform/index.ts":           webPlatformIndex(title),
		"web/platform/pages/" + title + "Page.tsx": webPlatformPage(title),
		"web/app/index.ts":               webAppIndex(title),
		"web/app/pages/" + title + "Page.tsx": webAppPage(title),
	}

	for path, content := range files {
		fullPath := filepath.Join(name, path)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", fullPath, err)
		}
		fmt.Printf("  created %s\n", path)
	}

	return nil
}

func toTitle(name string) string {
	parts := strings.Split(name, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}
