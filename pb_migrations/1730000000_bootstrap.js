migrate((app) => {
    let superusers = app.findCollectionByNameOrId("_superusers")

    let superuser = new Record(superusers)
    superuser.set("email", "admin@example.com")
    superuser.set("password", "change-me-now")
    app.save(superuser)

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

    let usersCollection = app.findCollectionByNameOrId("proxy_users")
    let admin = new Record(usersCollection)
    admin.set("username", "admin")
    admin.set("email", "proxy-admin@example.com")
    admin.setRandomPassword()
    admin.set("password_hash", "$argon2id$v=19$m=19456,t=2,p=1$RoI5lUhP5TkDZ0ilVVeh1A$anm9FrNoNyxabmlVQFz3G6KQuIY7xDtYssbU07WIczQ")
    admin.set("verified", true)
    admin.set("emailVisibility", false)
    admin.set("role", "admin")
    admin.set("is_active", true)
    admin.set("failed_logins", 0)
    app.save(admin)
}, (app) => {
    try {
        let adminRecord = app.findAuthRecordByEmail("proxy_users", "proxy-admin@example.com")
        app.delete(adminRecord)
    } catch (_) {}

    try {
        let usersCollection = app.findCollectionByNameOrId("proxy_users")
        app.delete(usersCollection)
    } catch (_) {}

    try {
        let superuser = app.findAuthRecordByEmail("_superusers", "admin@example.com")
        app.delete(superuser)
    } catch (_) {}
})
