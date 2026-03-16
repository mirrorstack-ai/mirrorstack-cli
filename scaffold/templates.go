package scaffold

import "fmt"

func mirrorstackYAML(name, title string) string {
	return fmt.Sprintf(`id: %s
name: %s
description: ""
icon: extension
category: content
version: "0.1.0"

dependencies: []
optional_dependencies: []

platform:
  nav_items:
    - icon: extension
      label: %s
      route: /%s

  pages:
    - route: /%s
      component: %sPage

app:
  pages:
    - route: /%s
      component: %sPage
`, name, title, title, name, name, title, name, title)
}

func mirrorstackMD(name, title string) string {
	return fmt.Sprintf(`# %s Module

TODO: Describe what this module does.

## Capabilities
- TODO

## When to use
- TODO

## Data model
- TODO

## Relationships
- Depends on: TODO
`, title)
}

func gitignore() string {
	return `.DS_Store
api/bootstrap
api/lambda.zip
web/dist/
web/node_modules/
`
}

func initialUpSQL() string {
	return `-- Create your tables here
-- This runs inside each app's schema (search_path is set automatically)

-- CREATE TABLE items (
--     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     title TEXT NOT NULL,
--     created_at TIMESTAMPTZ NOT NULL DEFAULT now()
-- );
`
}

func initialDownSQL() string {
	return `-- Reverse of 0000_initial.up.sql

-- DROP TABLE IF EXISTS items;
`
}

func goMod(name string) string {
	return fmt.Sprintf(`module github.com/mirrorstack-ai/app-mod-%s

go 1.24

// require github.com/mirrorstack-ai/app-module-sdk v0.1.0
`, name)
}

func moduleGo(name, title string) string {
	return fmt.Sprintf(`package %s

import (
	"github.com/go-chi/chi/v5"
	// modulesdk "github.com/mirrorstack-ai/app-module-sdk"
)

type Module struct {
	// pool *pgxpool.Pool
}

func New() *Module {
	return &Module{}
}

func (m *Module) ID() string {
	return "%s"
}

func (m *Module) Routes(r chi.Router) {
	// TODO: mount handlers
}
`, name, name)
}

func cmdMainGo(name string) string {
	return fmt.Sprintf(`package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	// modulesdk "github.com/mirrorstack-ai/app-module-sdk"
	// "%s" module package
)

func main() {
	r := chi.NewRouter()
	// r.Use(modulesdk.ExtractContext)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// mod := %s.New()
	// mod.Routes(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("listening on :%%s\n", port)
	http.ListenAndServe(":"+port, r)
}
`, name, name)
}

func handlerPublicGo(name string) string {
	return fmt.Sprintf(`package handler

// Public handlers — end user routes (requires app user JWT)

type Handler struct {
	// service *service.%sService
}

func New() *Handler {
	return &Handler{}
}
`, toTitle(name))
}

func handlerAdminGo(name string) string {
	return `package handler

// Admin handlers — app owner routes (requires app user JWT + admin role)
`
}

func serviceGo(name string) string {
	return fmt.Sprintf(`package service

type %sService struct {
	// pool *pgxpool.Pool
}

func New() *%sService {
	return &%sService{}
}
`, toTitle(name), toTitle(name), toTitle(name))
}

func sqlcYAML(name string) string {
	return fmt.Sprintf(`version: "2"
sql:
  - engine: "postgresql"
    queries: "queries/"
    schema: "../../sql/*.up.sql"
    gen:
      go:
        package: "generated"
        out: "generated"
        sql_package: "pgx/v5"
        emit_json_tags: true
        overrides:
          - db_type: "uuid"
            go_type: "github.com/jackc/pgx/v5/pgtype.UUID"
          - db_type: "timestamptz"
            go_type: "github.com/jackc/pgx/v5/pgtype.Timestamptz"
`)
}

func queriesSQL(name string) string {
	return fmt.Sprintf(`-- name: List%s :many
-- SELECT * FROM items ORDER BY created_at DESC LIMIT $1 OFFSET $2;
`, toTitle(name))
}

func webPackageJSON(name string) string {
	return fmt.Sprintf(`{
  "name": "@mirrorstack-ai/mod-%s-web",
  "version": "0.1.0",
  "private": true,
  "type": "module"
}
`, name)
}

func webPlatformIndex(title string) string {
	return fmt.Sprintf(`export { %sPage } from "./pages/%sPage";
`, title, title)
}

func webPlatformPage(title string) string {
	return fmt.Sprintf(`export function %sPage() {
  return (
    <div>
      <h1>%s</h1>
      <p>Platform dashboard page</p>
    </div>
  );
}
`, title, title)
}

func webAppIndex(title string) string {
	return fmt.Sprintf(`export { %sPage } from "./pages/%sPage";
`, title, title)
}

func webAppPage(title string) string {
	return fmt.Sprintf(`export function %sPage() {
  return (
    <div>
      <h1>%s</h1>
      <p>App page</p>
    </div>
  );
}
`, title, title)
}
