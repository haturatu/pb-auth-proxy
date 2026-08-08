migrate((app) => {
    let users = app.findCollectionByNameOrId("proxy_users")

    if (users.fields.fieldNames().indexOf("password_hash") === -1) {
        users.fields.add(new TextField({
            name: "password_hash",
            type: "text",
            max: 255,
        }))
    }
    users.passwordAuth.enabled = false

    app.save(users)
}, (app) => {
    let users = app.findCollectionByNameOrId("proxy_users")
    users.fields.removeByName("password_hash")
    app.save(users)
})
