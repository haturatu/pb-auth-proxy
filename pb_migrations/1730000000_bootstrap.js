migrate((app) => {
    // Never create a PocketBase superuser with a known password.
    // Provision one explicitly with `pocketbase superuser upsert`.

    let users = new Collection({
        type: "auth",
        name: "proxy_users",
        listRule: null,
        viewRule: null,
        createRule: "",
        updateRule: "@request.auth.id = id",
        deleteRule: null,
        fields: [
            {
                name: "username",
                type: "text",
                required: true,
                presentable: true,
                min: 3,
                max: 64,
                pattern: "^[a-zA-Z0-9_.-]+$",
            },
            {
                name: "role",
                type: "select",
                required: true,
                maxSelect: 1,
                values: ["user", "admin"],
            },
            {
                name: "is_active",
                type: "bool",
            },
            {
                name: "failed_logins",
                type: "number",
                onlyInt: true,
                min: 0,
            },
            {
                name: "last_login_at",
                type: "date",
            },
            {
                name: "password_hash",
                type: "text",
                max: 255,
            },
        ],
        indexes: [
            "CREATE UNIQUE INDEX idx_proxy_users_username ON proxy_users (username)",
        ],
        passwordAuth: {
            enabled: false,
        },
    })
    app.save(users)

    // Create the first proxy administrator explicitly with /app/admin-cli.
    // A fixed Argon2 hash would expose a shared login in every deployment.
}, (app) => {
    try {
        let usersCollection = app.findCollectionByNameOrId("proxy_users")
        app.delete(usersCollection)
    } catch (_) {}

})
