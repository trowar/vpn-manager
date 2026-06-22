# Web Admin Call Chains

## Request Setup

1. `wsgi.py`
2. `app.py`
3. `bootstrap()`
4. `ensure_db()`, `ensure_admin_user()`
5. Flask request handlers use `get_db()` from `portal_db.py`

## Admin Login

1. Browser opens `/`
2. `index()` shows the video-style cover page
3. User types `admin`, UI opens login modal
4. Login submits to `/api/login`
5. `api_login()`
6. `validate_captcha_input_impl()`
7. `authenticate_user()`
8. `login_user_session()`
9. Redirect or JSON response points to `/admin`

## Admin Dashboard

1. Browser opens `/admin`
2. `admin_panel()`
3. `admin_required`
4. `admin_must_change_password()`
5. `load_version_nav_state()`
6. Render `templates/admin.html`

## User List

1. Browser opens `/admin/subscriptions`
2. `admin_subscriptions()`
3. Load users from PostgreSQL
4. Load online data through runtime helpers
5. `decorate_admin_subscription_row()`
6. Render `templates/admin_subscriptions.html`

## Create User

1. Modal submits `/admin/users/create`
2. `admin_create_user()`
3. Validate username and password rules
4. Insert user row
5. `save_user_server_permissions()`
6. `ensure_user_transport_ports()`
7. Redirect to `/admin/subscriptions`

## Enable Or Disable User

1. Button submits `/admin/users/<id>/enable` or `/admin/users/<id>/disable`
2. `admin_enable_user()` or `admin_disable_user()`
3. Update account status
4. VPN status follows account status
5. Redirect to `/admin/subscriptions`

## Server List

1. Browser opens `/admin/servers`
2. `admin_servers()`
3. `refresh_missing_server_regions()`
4. `load_admin_servers()`
5. Render `templates/admin_servers.html`

## Server Save

1. Form submits `/admin/servers/create` or `/admin/servers/<id>/update`
2. `admin_create_server()` or `admin_update_saved_server()`
3. Normalize host, region, SSH port, relay ports, and deploy modes
4. Save server row
5. If the server is already deployed, trigger redeploy path
6. Redirect to `/admin/servers`

## Server Deploy

1. Button submits `/admin/servers/<id>/deploy`
2. `admin_deploy_saved_server()`
3. `deploy_server_task()`
4. SSH connection uses server credentials
5. Remote scripts install selected services
6. Deploy log is written through `portal_services/deploy_logs.py`
7. Server row deployment status is updated

