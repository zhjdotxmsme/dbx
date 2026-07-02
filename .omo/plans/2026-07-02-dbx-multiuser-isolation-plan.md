# 实施计划：DBX 多用户数据隔离与权限强制

设计文档: `docs/superpowers/specs/2026-07-02-dbx-multiuser-isolation-design.md`
目标分支: `feat--zhuhj`
预计 5 个 PR，按依赖顺序提交

## 全局前置（PR0 之前完成）

不占 PR，但需要先做：

- [ ] 确认 `feat--zhuhj` 分支已同步远程（`git pull origin feat--zhuhj`）
- [ ] 确认本地 Docker 构建可用（之前修复的 strum/chrono 已合并）
- [ ] 读设计文档 §一 ~ §十 完整一遍

---

## PR 1: 数据模型层（无破坏性）

目标：完成所有 schema 变更 + 结构体字段添加 + SQLite 自动迁移逻辑。不动 storage 方法签名，不动路由。**PR 结尾 cargo build 应通过。**

### 1.1 PostgreSQL migrations

- [ ] **新建** `crates/dbx-web/migrations/0006_create_role_connections.sql`：
  - `roles` 表加 `ldap_group_dn` 已存在（设计文档 §4.1.3）
  - 创建 `role_connections` 表（角色 ↔ connection_id 关联）
  - 创建 `idx_role_connections_role_id` 和 `idx_role_connections_connection_id`
  - 创建 `everyone` 角色（`INSERT ... ON CONFLICT DO NOTHING`，name='everyone'）
- [ ] **新建** `crates/dbx-web/migrations/0007_create_audit_log.sql`：
  - `audit_log` 表（actor_id、action、target_user_id、target_resource_id、metadata_json、ip_address、created_at）
  - 索引：actor_id、target_user_id、created_at DESC
- [ ] **新建** `crates/dbx-web/migrations/0008_create_user_connection_overrides.sql`（本期预留，不使用）：
  - 仅创建表 + 注释说明"细粒度 ACL 超出本期范围"
  - 防止未来迁移文件序号冲突

**验证**：
```bash
cd deploy
docker compose up -d postgres
docker exec -it dbx-postgres-1 psql -U dbx -d dbx \
  -f /docker-entrypoint-initdb.d/../migrations/0006_create_role_connections.sql
# 期望无错误，role_connections 表和 everyone 角色都创建
```

### 1.2 SQLite schema（核心加列）

- [ ] **修改** `crates/dbx-core/src/storage.rs` 的 `SCHEMA_STATEMENTS`：
  - `history` 表 schema 加 `user_id TEXT NOT NULL DEFAULT ''`
  - `ai_conversations` 表 schema 加 `user_id TEXT NOT NULL DEFAULT ''`
  - `saved_sql_folders` 表 schema 加 `user_id TEXT NOT NULL DEFAULT ''`
  - `saved_sql_files` 表 schema 加 `user_id TEXT NOT NULL DEFAULT ''`
- [ ] **新增** 函数 `ensure_user_id_columns_sync(conn: &Connection) -> Result<(), String>`：
  - 复用 `ensure_table_columns` 辅助函数
  - 给 4 个表加 `user_id` 列
  - 幂等（检查列是否存在）
- [ ] 在 `init_schema` 末尾调用 `ensure_user_id_columns_sync(conn)?;`

**验证**：
```bash
# 删老 SQLite 库重新生成
rm -f data/dbx.db*
cargo run -p dbx-web
sqlite3 data/dbx.db ".schema history"
# 期望看到 user_id TEXT NOT NULL DEFAULT ''
```

### 1.3 结构体字段添加

- [ ] **修改** `crates/dbx-core/src/history.rs` 的 `HistoryEntry`：
  - 加 `pub user_id: String` + `#[serde(default)]`
- [ ] **修改** `crates/dbx-core/src/saved_sql.rs` 的 `SavedSqlFolder` 和 `SavedSqlFile`：
  - 两个结构体都加 `pub user_id: String` + `#[serde(default)]`
- [ ] **修改** `crates/dbx-core/src/ai.rs` 的 `AiConversation`：
  - 加 `pub user_id: String` + `#[serde(default)]`

**验证**：
```bash
cargo check -p dbx-core
# 期望：零错误（即使老反序列化无 user_id 也能正常工作）
```

### 1.4 提交

```bash
git checkout -b feat/isolation-data-model
git add crates/dbx-web/migrations/0006_*.sql \
        crates/dbx-web/migrations/0007_*.sql \
        crates/dbx-web/migrations/0008_*.sql \
        crates/dbx-core/src/storage.rs \
        crates/dbx-core/src/history.rs \
        crates/dbx-core/src/saved_sql.rs \
        crates/dbx-core/src/ai.rs

git commit -m "feat(isolation): add user_id columns and RBAC tables

- SQLite: add user_id column to history/ai_conversations/saved_sql_*
- SQLite: ensure_user_id_columns_sync for zero-downtime migration
- PostgreSQL: role_connections + audit_log + user_connection_overrides
- Struct fields: user_id with #[serde(default)] for backward compat"

git push origin feat/isolation-data-model
```

**PR 结尾 cargo build 应通过**。`User: New` 表 user_id 为 `''`（视为"未认领"，admin 模式可读）。

---

## PR 2: Storage 方法签名改造（编译期强制）

目标：改 13 个 storage 方法签名为 `Option<&str>` 过滤。**这步会触发编译错误，强制所有调用方在 PR 3 更新。**

**重要**：本 PR 故意让代码不能编译。单独 checkout 这个 PR 不应 merge。

### 2.1 Storage 方法签名

- [ ] **修改** `crates/dbx-core/src/storage.rs`：
  - `load_history_entries(limit)` → `load_history_entries(user_id: Option<&str>, limit)`
  - `save_history_entry(entry)` → `save_history_entry(entry, session_user_id: &str)`（强制覆盖）
  - `delete_history_entry(id)` → `delete_history_entry(id, session_user_id: &str)`（防越权删）
  - `load_ai_conversations()` → `load_ai_conversations(user_id: Option<&str>)`
  - `save_ai_conversation(conv)` → `save_ai_conversation(conv, session_user_id: &str)`
  - `delete_ai_conversation(id)` → `delete_ai_conversation(id, session_user_id: &str)`
  - `load_saved_sql_library()` → `load_saved_sql_library(user_id: Option<&str>)`
  - `load_saved_sql_library_summary()` → `load_saved_sql_library_summary(user_id: Option<&str>)`
  - `load_saved_sql_file(id)` → `load_saved_sql_file(id, user_id: &str)`
  - `save_saved_sql_folder(folder)` → `save_saved_sql_folder(folder, session_user_id: &str)`
  - `delete_saved_sql_folder(id)` → `delete_saved_sql_folder(id, user_id: &str)`
  - `save_saved_sql_file(file)` → `save_saved_sql_file(file, session_user_id: &str)`
  - `delete_saved_sql_file(id)` → `delete_saved_sql_file(id, user_id: &str)`
- [ ] 所有 SELECT 加 `WHERE user_id = ?` 过滤（`Option<&str>::is_none()` 时跳过）
- [ ] 所有 INSERT 在写时用 `session_user_id` 覆盖 `entry.user_id`（防伪造）
- [ ] 所有 DELETE 在 `WHERE id = ?` 后追加 `AND user_id = ?`

**验证**：
```bash
cargo check -p dbx-web
# 期望：12+ 个调用方错误（每个路由 handler 一个错误）
```

### 2.2 UserRepository 角色方法

- [ ] **修改** `crates/dbx-web/src/repositories/user_repository.rs`：
  - 新增 `get_user_role_ids(user_id) -> Vec<Uuid>`
  - 新增 `get_connection_ids_for_roles(role_ids) -> Vec<String>`
  - 新增 `user_can_access_connection(user_id, connection_id, is_admin) -> bool`
  - 新增 `grant_connection_to_role(role_id, connection_id, granted_by) -> Result<()>`
  - 新增 `revoke_connection_from_role(role_id, connection_id) -> Result<()>`
  - 新增 `list_role_connections(role_id) -> Vec<String>`
  - 新增 `find_role_by_name_everyone_inclusive(role_ids) -> Vec<Uuid>`（把 everyone 角色加入）
  - 新增 `create_role_if_missing(name, description) -> Result<Uuid>`
  - 新增 `log_audit(...)`（或独立 audit 模块，本期放这里）

### 2.3 提交

```bash
git checkout -b feat/isolation-storage-signatures
git add crates/dbx-core/src/storage.rs \
        crates/dbx-web/src/repositories/user_repository.rs

git commit -m "refactor(storage): add user_id filter to all per-user methods

- 13 storage methods now take Option<&str> user_id or &str session_user_id
- UserRepository: new role/connection helpers
- This commit intentionally breaks callers; PR 3 fixes them"

git push origin feat/isolation-storage-signatures
```

**PR 2 结尾 cargo build 仍失败**（设计如此）。

---

## PR 3: 路由层集成（恢复编译 + 接入权限）

目标：修复 PR 2 引入的编译错误。在所有路由处理器加 `user: AuthenticatedUser` extractor，调用 storage 时传入 user_id。**PR 结尾 cargo build 通过。**

### 3.1 AuthenticatedUser 提取（必备前置）

- [ ] 确认 `crates/dbx-web/src/auth/middleware.rs` 的 `AuthenticatedUser` 已被 `auth_middleware` 注入到 `request.extensions()`
- [ ] 在 `routes/history.rs`、`routes/ai.rs`、`routes/saved_sql.rs` 全部 handler 签名加 `user: AuthenticatedUser`

### 3.2 历史路由（routes/history.rs）

- [ ] `save_history`：加 `user: AuthenticatedUser`，调用 `storage.save_history_entry(&entry, &user.id.to_string())`
- [ ] `load_history`：加 `user: AuthenticatedUser`，加 `Query<HistoryQuery>`，调 `resolve_user_filter` 决定 filter
- [ ] `delete_history_entry`：加 `user: AuthenticatedUser`，传 user_id 给 storage

### 3.3 AI 路由（routes/ai.rs）

- [ ] `save_ai_conversation`：加 user extractor，强制覆盖 conv.user_id
- [ ] `load_ai_conversations`：加 user + as_user 参数
- [ ] `delete_ai_conversation`：加 user extractor

### 3.4 Saved SQL 路由（routes/saved_sql.rs）

- [ ] 全部 6 个 handler 加 user extractor
- [ ] load 走 user_id 过滤，save/delete 强制 user_id

### 3.5 resolve_user_filter helper

- [ ] **新增** `crates/dbx-web/src/auth/middleware.rs` 末尾（或独立 `auth/filters.rs`）：
  - `pub fn resolve_user_filter(user, as_user, all) -> Result<(Option<String>, Option<Uuid>), AppError>`
  - 非 admin 传 as_user → 403
  - admin + as_user → 校验 Uuid 存在性 + is_active → 400/404
  - admin + all=true → (None, None)
  - admin 无参数 → (Some(self.id), None)
  - 非 admin 无参数 → (Some(self.id), None)

### 3.6 路由层 audit 写入

- [ ] **新增** `crates/dbx-web/src/audit.rs`（独立模块）：
  - `log_audit(pool, actor_id, action, target_user_id, target_resource_id, metadata, ip) -> Result<()>` 写入 `audit_log` 表
  - `try_log_audit(...)` 包装，失败时返回 Ok 但标 `X-Audit-Log-Failed: true` 提示（用 `tracing::error!` 记录失败原因）
- [ ] 在 `load_history` / `load_ai_conversations` / `load_saved_sql_library` 等可能跨用户访问的路由处理器里调 `try_log_audit`：
  ```rust
  if let Some(target) = audit_target {
      try_log_audit(&state.pg_pool, user.id, "view_user_history", Some(target), None, None, ip).await;
  }
  ```
- [ ] 响应头加 `X-Audit-Log-Failed: true`（axum 的 `IntoResponse::with_headers` 或中间件）

### 3.7 WebState 初始化补全

- [ ] **修改** `crates/dbx-web/src/main.rs:198` 构造 WebState：
  - 加 `pg_pool: pg_pool.clone()`
  - 加 `auth_service: Some(Arc::new(auth_service))`
  - 加 `config: Arc::new(config)`

### 3.8 提交

```bash
git checkout -b feat/isolation-routes
git add crates/dbx-web/src/routes/ \
        crates/dbx-web/src/auth/ \
        crates/dbx-web/src/audit.rs \
        crates/dbx-web/src/main.rs

git commit -m "feat(isolation): enforce user_id filtering in route handlers

- All per-user routes extract AuthenticatedUser from extensions
- storage calls now pass session user_id (or wildcard for admin)
- resolve_user_filter handles as_user/all/admin authorization
- audit module writes to audit_log; failures surface X-Audit-Log-Failed header
- WebState now initializes pg_pool/auth_service/config"

git push origin feat/isolation-routes
```

**PR 3 结尾 cargo build 应通过**。手动测试：admin 登录→调 `/api/history`→自己列表有数据。`as_user=其他用户id`→返回该用户 history + 写 audit_log。

---

## PR 4: 连接 ACL + RequirePermission（功能完成）

目标：实现连接可见性过滤、角色分配 API、RequirePermission 接入关键路由。

### 4.1 连接可见性过滤

- [ ] **修改** `crates/dbx-web/src/routes/connection.rs`：
  - `load_connections` 改名为 `load_connections_for_user(user: AuthenticatedUser)`
  - 非 admin 用户：`user_repo.get_connection_ids_for_user(...)` → `storage.load_connections_by_ids(&ids)`
  - admin：直接 `storage.load_connections()`
  - 加 `RequirePermission(ConnectionRead)` extractor
- [ ] **修改** `load_connections` SQL 路径：新增 `load_connections_by_ids(&[String])` 在 `storage.rs`

### 4.2 连接管理 API

- [ ] **新建** `crates/dbx-web/src/routes/role_connections.rs`：
  - `POST /api/role-connections/grant` — `{role_id, connection_id}` → grant
  - `POST /api/role-connections/revoke` — 同 body → revoke
  - `GET /api/role-connections?role_id=xxx` → 列出某角色的连接
  - 全部加 `RequirePermission(UserManage)`
- [ ] 在 `routes/mod.rs` 加 `pub mod role_connections;`
- [ ] 在 `main.rs` 注册路由

### 4.3 用户管理 API

- [ ] **新建** `crates/dbx-web/src/routes/users.rs`：
  - `GET /api/users` — 列出所有用户（带角色）
  - `POST /api/users/{id}/roles` — 分配角色
  - `DELETE /api/users/{id}/roles/{role_id}` — 撤销
  - 全部加 `RequirePermission(UserManage)`

### 4.4 RequirePermission 接入

按设计文档 §4.5.2 表格：

- [ ] `POST /api/connection/save` — `RequirePermission(ConnectionWrite)`
- [ ] `DELETE /api/connection/{id}` — `RequirePermission(ConnectionDelete)`
- [ ] `POST /api/connection/test` — `RequirePermission(ConnectionRead)`
- [ ] `POST /api/query/execute` — `RequirePermission(QueryExecute)` + `user_can_access_connection(...)` 检查
- [ ] `POST /api/transfer/start` — `RequirePermission(QueryExecute)` + `user_can_access_connection(...)`
- [ ] `POST /api/saved-sql`（file/folder save） — `RequirePermission(SavedSqlWrite)`
- [ ] `DELETE /api/saved-sql/{id}` — `RequirePermission(SavedSqlWrite)`
- [ ] `POST /api/ai/stream` — `RequirePermission(AiUse)`
- [ ] `POST /api/settings/save` — `RequirePermission(SettingsWrite)`
- [ ] 所有新加的 users/role-connections API — `RequirePermission(UserManage)`

### 4.5 提交

```bash
git checkout -b feat/isolation-acl
git add crates/dbx-web/src/routes/connection.rs \
        crates/dbx-web/src/routes/role_connections.rs \
        crates/dbx-web/src/routes/users.rs \
        crates/dbx-web/src/routes/mod.rs \
        crates/dbx-web/src/main.rs \
        crates/dbx-core/src/storage.rs

git commit -m "feat(acl): role-based connection visibility and route permissions

- load_connections now filters by user role grants
- New /api/role-connections/* APIs (UserManage permission)
- New /api/users/* APIs (UserManage permission)
- RequirePermission integrated on 10 sensitive routes
- query/transfer routes also check user_can_access_connection"

git push origin feat/isolation-acl
```

---

## PR 5: 启动时 post-migration + 集成测试

目标：实现设计文档 §4.4.1.1 的 `run_post_migration`，跑集成测试验证。

### 5.1 post-migration

- [ ] **新增** `crates/dbx-web/src/migrations.rs`：
  - `pub async fn run_post_migration(state: &WebState) -> Result<()>`：
    1. `create_role_if_missing("everyone", ...)`
    2. `app.storage.list_all_connection_ids()` 从 SQLite 读
    3. 把每个 conn grant 给 everyone 角色
    4. `tracing::info!` 记录
- [ ] 在 `main.rs` 启动序列中、auth_service 初始化之后调一次：
  ```rust
  run_post_migration(&web_state).await?;
  ```
- [ ] 幂等：重复启动不会重复 grant（`ON CONFLICT DO NOTHING`）

### 5.2 集成测试（testcontainers / 直接用 docker-compose 起 PostgreSQL）

- [ ] **新建** `crates/dbx-web/tests/isolation.rs`：
  - Test 1: Viewer 调 `POST /api/connection/save` → 403
  - Test 2: Editor 调 `DELETE /api/connection/{id}` → 403
  - Test 3: 用户 A 调 `GET /api/history` → 只看到 A 的记录
  - Test 4: admin 调 `GET /api/history?as_user=A_id` → 看到 A 的记录 + audit_log 写入
  - Test 5: 用户 A 调 `POST /api/saved-sql`（folder 属于 B）→ 403
  - Test 6: admin 调 `GET /api/connection/list` → 看到所有连接；Editor 只能看到角色授予的连接
  - Test 7: post-migration 后非 admin 用户仍能看到所有连接（everyone 角色）
  - Test 8: user_can_access_connection 对 Editor 返回 false 当 connection 不在角色
  - Test 9: 单元测试 — resolve_user_filter 在各种输入下返回正确
  - Test 10: 单元测试 — RoleKey::permissions() 各角色集合正确

### 5.3 文档更新

- [ ] **修改** `deploy/.env.example`：
  - 不变（认证配置已在 PR0 之前）
- [ ] **修改** `README.md`（如果有 `Multi-user deployment` 章节）：
  - 加说明：默认所有用户通过 LDAP 登录，admin 通过 LDAP group 授予角色
  - 升级说明：升级后现有连接自动对所有用户可见，admin 可逐个 revoke

### 5.4 提交

```bash
git checkout -b feat/isolation-migration-tests
git add crates/dbx-web/src/migrations.rs \
        crates/dbx-web/src/main.rs \
        crates/dbx-web/tests/isolation.rs \
        README.md

git commit -m "test(isolation): post-migration and integration tests

- run_post_migration grants existing connections to 'everyone' role
- 10 integration tests covering permission enforcement, user isolation,
  admin as_user audit, and migration behavior
- README updated with multi-user deployment notes"

git push origin feat/isolation-migration-tests
```

---

## 合并策略

5 个 PR 都完成后：

```bash
git checkout feat--zhuhj
git merge feat/isolation-data-model
git merge feat/isolation-storage-signatures
git merge feat/isolation-routes
git merge feat/isolation-acl
git merge feat/isolation-migration-tests
git push origin feat--zhuhj
```

合并到 `feat--zhuhj` 后部署到测试服务器跑：
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
# 验证：登录两个 LDAP 用户，一个 admin 一个普通，确认隔离生效
```

---

## 风险与回滚

| 风险 | 缓解 |
|------|------|
| PR 2 编译期破坏（预期） | PR 3 紧跟修复，单独 PR 2 不应 merge |
| post-migration 失败 | 启动日志要醒目；提供 `--skip-post-migration` flag 跳过（紧急回滚） |
| 老 SQLite 库 `user_id=''` 数据 admin 模式可见，普通用户看不到 | 文档说明 + 提供 admin CLI 工具重新分配（后续工作） |
| 性能影响（每查询加 `WHERE user_id`） | user_id 加索引（PR 1 schema 已含） |
| LDAP 用户的 user_id 格式（username vs UUID） | storage 用 `&str`，调用方传 `user.id.to_string()` 保持 UUID 一致 |

---

## 成功标准

- [ ] 5 个 PR 全部 merge 到 `feat--zhuhj`
- [ ] `cargo build -p dbx-web` 通过
- [ ] 10 个集成测试全部通过
- [ ] 升级现有部署：老连接对所有非 admin 用户仍可见
- [ ] admin 跨用户访问写入 audit_log
- [ ] 文档同步更新

## 不在本计划范围

- 前端 UI 改造（连接分配界面、审计 dashboard）
- 多实例/集群部署
- 自动过期/清理 audit_log
- LDAP group → 角色映射的配置化（目前硬编码：everyone/viewer/editor/admin 由 LDAP 同步逻辑决定）
- 单元测试覆盖率提升（本期只加集成测试，单元测试看后续）
