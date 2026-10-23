migrate((app) => {
    const users = app.findCollectionByNameOrId("proxy_users")
    // All user mutations must pass through the proxy, including roles and passwords.
    users.createRule = null
    users.updateRule = null
    users.fields.add(new DateField({name: "locked_until"}))
    users.fields.add(new TextField({name: "auth_version", max: 64}))
    app.save(users)

    const owner = {name: "user_id", type: "relation", required: true, collectionId: users.id, maxSelect: 1, cascadeDelete: true}
    const locked = {type: "base", listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null}
    app.save(new Collection(Object.assign({}, locked, {
        name: "auth_tokens",
        fields: [owner,
            {name: "token_hash", type: "text", required: true, max: 64},
            {name: "token_type", type: "text", required: true, max: 16},
            {name: "auth_version", type: "text", max: 64},
            {name: "expires_at", type: "date", required: true},
            {name: "authenticated_at", type: "date", required: true}],
        indexes: ["CREATE UNIQUE INDEX idx_auth_tokens_hash ON auth_tokens (token_hash)",
            "CREATE INDEX idx_auth_tokens_expiry ON auth_tokens (expires_at)"]
    })))
    // PocketBase DELETE can return success to concurrent callers that loaded the
    // same record. A unique insert is the atomic winner election for consumption.
    app.save(new Collection(Object.assign({}, locked, {
        name: "auth_consumptions",
        fields: [
            {name: "key_hash", type: "text", required: true, max: 64},
            {name: "expires_at", type: "date", required: true}],
        indexes: ["CREATE UNIQUE INDEX idx_consumption_key ON auth_consumptions (key_hash)",
            "CREATE INDEX idx_consumption_expiry ON auth_consumptions (expires_at)"]
    })))
    app.save(new Collection(Object.assign({}, locked, {
        name: "passkey_credentials",
        fields: [owner,
            {name: "credential_id", type: "text", required: true, max: 2048},
            {name: "rp_id", type: "text", required: true, max: 253},
            {name: "credential_data", type: "json", required: true, maxSize: 65536},
            {name: "revoked", type: "bool"},
            {name: "name", type: "text", required: true, max: 100},
            {name: "created_at", type: "date", required: true},
            {name: "last_used_at", type: "date"}],
        indexes: ["CREATE UNIQUE INDEX idx_passkey_credential_id ON passkey_credentials (credential_id)",
            "CREATE INDEX idx_passkey_user ON passkey_credentials (user_id)"]
    })))
    app.save(new Collection(Object.assign({}, locked, {
        name: "webauthn_ceremonies",
        fields: [
            {name: "key_hash", type: "text", required: true, max: 64},
            {name: "binding", type: "text", required: true, max: 64},
            {name: "kind", type: "text", required: true, max: 16},
            {name: "user_id", type: "text", max: 64},
            {name: "name", type: "text", max: 100},
            {name: "session_data", type: "json", required: true, maxSize: 65536},
            {name: "expires_at", type: "date", required: true}],
        indexes: ["CREATE UNIQUE INDEX idx_ceremony_key ON webauthn_ceremonies (key_hash)",
            "CREATE INDEX idx_ceremony_expiry ON webauthn_ceremonies (expires_at)"]
    })))
}, (app) => {
    for (const name of ["webauthn_ceremonies", "passkey_credentials", "auth_consumptions", "auth_tokens"]) {
        app.delete(app.findCollectionByNameOrId(name))
    }
    const users = app.findCollectionByNameOrId("proxy_users")
    users.fields.removeByName("locked_until")
    users.fields.removeByName("auth_version")
    app.save(users)
})
