//! Static templates for the module scaffold. The Go version inlined
//! these as fmt.Sprintf calls; we keep the same shape (raw-string
//! literals + format! for substitutions) so the diff is reviewable
//! against scaffold/templates.go in the Go reference.

/// Returns (relative_path, file_contents) pairs for every file the
/// scaffold creates.
pub fn files(name: &str, title: &str) -> Vec<(String, String)> {
    vec![
        ("mirrorstack.yaml".into(), mirrorstack_yaml(name, title)),
        ("MIRRORSTACK.md".into(), mirrorstack_md(title)),
        (".gitignore".into(), gitignore().into()),
        ("sql/0000_initial.up.sql".into(), initial_up_sql().into()),
        ("sql/0000_initial.down.sql".into(), initial_down_sql().into()),
        ("api/go.mod".into(), go_mod(name)),
        ("api/module.go".into(), module_go(name)),
        ("api/cmd/main.go".into(), cmd_main_go(name)),
        ("api/handler/public.go".into(), handler_public_go(title)),
        ("api/handler/admin.go".into(), handler_admin_go().into()),
        (format!("api/service/{name}.go"), service_go(title)),
        ("api/db/sqlc.yaml".into(), sqlc_yaml().into()),
        (format!("api/db/queries/{name}.sql"), queries_sql(title)),
        ("web/package.json".into(), web_package_json(name)),
        ("web/platform/index.ts".into(), web_index(title)),
        (format!("web/platform/pages/{title}Page.tsx"), web_platform_page(title)),
        ("web/app/index.ts".into(), web_index(title)),
        (format!("web/app/pages/{title}Page.tsx"), web_app_page(title)),
    ]
}

fn mirrorstack_yaml(name: &str, title: &str) -> String {
    format!(
        "id: {name}\n\
         name: {title}\n\
         description: \"\"\n\
         icon: extension\n\
         category: content\n\
         version: \"0.1.0\"\n\
         \n\
         dependencies: []\n\
         optional_dependencies: []\n\
         \n\
         platform:\n\
           nav_items:\n\
             - icon: extension\n\
               label: {title}\n\
               route: /{name}\n\
         \n\
           pages:\n\
             - route: /{name}\n\
               component: {title}Page\n\
         \n\
         app:\n\
           pages:\n\
             - route: /{name}\n\
               component: {title}Page\n",
    )
}

fn mirrorstack_md(title: &str) -> String {
    format!(
        "# {title} Module\n\
         \n\
         TODO: Describe what this module does.\n\
         \n\
         ## Capabilities\n\
         - TODO\n\
         \n\
         ## When to use\n\
         - TODO\n\
         \n\
         ## Data model\n\
         - TODO\n\
         \n\
         ## Relationships\n\
         - Depends on: TODO\n",
    )
}

fn gitignore() -> &'static str {
    ".DS_Store\n\
     api/bootstrap\n\
     api/lambda.zip\n\
     web/dist/\n\
     web/node_modules/\n"
}

fn initial_up_sql() -> &'static str {
    "-- Create your tables here\n\
     -- This runs inside each app's schema (search_path is set automatically)\n\
     \n\
     -- CREATE TABLE items (\n\
     --     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n\
     --     title TEXT NOT NULL,\n\
     --     created_at TIMESTAMPTZ NOT NULL DEFAULT now()\n\
     -- );\n"
}

fn initial_down_sql() -> &'static str {
    "-- Reverse of 0000_initial.up.sql\n\
     \n\
     -- DROP TABLE IF EXISTS items;\n"
}

fn go_mod(name: &str) -> String {
    format!(
        "module github.com/mirrorstack-ai/app-mod-{name}\n\
         \n\
         go 1.24\n\
         \n\
         // require github.com/mirrorstack-ai/app-module-sdk v0.1.0\n",
    )
}

fn module_go(name: &str) -> String {
    format!(
        "package {name}\n\
         \n\
         import (\n\
         \t\"github.com/go-chi/chi/v5\"\n\
         \t// modulesdk \"github.com/mirrorstack-ai/app-module-sdk\"\n\
         )\n\
         \n\
         type Module struct {{\n\
         \t// pool *pgxpool.Pool\n\
         }}\n\
         \n\
         func New() *Module {{\n\
         \treturn &Module{{}}\n\
         }}\n\
         \n\
         func (m *Module) ID() string {{\n\
         \treturn \"{name}\"\n\
         }}\n\
         \n\
         func (m *Module) Routes(r chi.Router) {{\n\
         \t// TODO: mount handlers\n\
         }}\n",
    )
}

fn cmd_main_go(name: &str) -> String {
    format!(
        "package main\n\
         \n\
         import (\n\
         \t\"fmt\"\n\
         \t\"net/http\"\n\
         \t\"os\"\n\
         \n\
         \t\"github.com/go-chi/chi/v5\"\n\
         \t// modulesdk \"github.com/mirrorstack-ai/app-module-sdk\"\n\
         \t// \"{name}\" module package\n\
         )\n\
         \n\
         func main() {{\n\
         \tr := chi.NewRouter()\n\
         \t// r.Use(modulesdk.ExtractContext)\n\
         \n\
         \tr.Get(\"/health\", func(w http.ResponseWriter, r *http.Request) {{\n\
         \t\tw.Write([]byte(\"ok\"))\n\
         \t}})\n\
         \n\
         \t// mod := {name}.New()\n\
         \t// mod.Routes(r)\n\
         \n\
         \tport := os.Getenv(\"PORT\")\n\
         \tif port == \"\" {{\n\
         \t\tport = \"8080\"\n\
         \t}}\n\
         \n\
         \tfmt.Printf(\"listening on :%s\\n\", port)\n\
         \thttp.ListenAndServe(\":\"+port, r)\n\
         }}\n",
    )
}

fn handler_public_go(title: &str) -> String {
    format!(
        "package handler\n\
         \n\
         // Public handlers — end user routes (requires app user JWT)\n\
         \n\
         type Handler struct {{\n\
         \t// service *service.{title}Service\n\
         }}\n\
         \n\
         func New() *Handler {{\n\
         \treturn &Handler{{}}\n\
         }}\n",
    )
}

fn handler_admin_go() -> &'static str {
    "package handler\n\
     \n\
     // Admin handlers — app owner routes (requires app user JWT + admin role)\n"
}

fn service_go(title: &str) -> String {
    format!(
        "package service\n\
         \n\
         type {title}Service struct {{\n\
         \t// pool *pgxpool.Pool\n\
         }}\n\
         \n\
         func New() *{title}Service {{\n\
         \treturn &{title}Service{{}}\n\
         }}\n",
    )
}

fn sqlc_yaml() -> &'static str {
    "version: \"2\"\n\
     sql:\n\
       - engine: \"postgresql\"\n\
         queries: \"queries/\"\n\
         schema: \"../../sql/*.up.sql\"\n\
         gen:\n\
           go:\n\
             package: \"generated\"\n\
             out: \"generated\"\n\
             sql_package: \"pgx/v5\"\n\
             emit_json_tags: true\n\
             overrides:\n\
               - db_type: \"uuid\"\n\
                 go_type: \"github.com/jackc/pgx/v5/pgtype.UUID\"\n\
               - db_type: \"timestamptz\"\n\
                 go_type: \"github.com/jackc/pgx/v5/pgtype.Timestamptz\"\n"
}

fn queries_sql(title: &str) -> String {
    format!(
        "-- name: List{title} :many\n\
         -- SELECT * FROM items ORDER BY created_at DESC LIMIT $1 OFFSET $2;\n",
    )
}

fn web_package_json(name: &str) -> String {
    format!(
        "{{\n  \"name\": \"@mirrorstack-ai/mod-{name}-web\",\n  \"version\": \"0.1.0\",\n  \"private\": true,\n  \"type\": \"module\"\n}}\n",
    )
}

fn web_index(title: &str) -> String {
    format!("export {{ {title}Page }} from \"./pages/{title}Page\";\n")
}

fn web_platform_page(title: &str) -> String {
    format!(
        "export function {title}Page() {{\n  return (\n    <div>\n      <h1>{title}</h1>\n      <p>Platform dashboard page</p>\n    </div>\n  );\n}}\n",
    )
}

fn web_app_page(title: &str) -> String {
    format!(
        "export function {title}Page() {{\n  return (\n    <div>\n      <h1>{title}</h1>\n      <p>App page</p>\n    </div>\n  );\n}}\n",
    )
}
