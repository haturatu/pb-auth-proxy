<?php
    $paths = [
        'AccountPassword' => $_SERVER['AUTH_PATH_ACCOUNT_PASSWORD'] ?? '/account/password',
        'Admin' => $_SERVER['AUTH_PATH_ADMIN'] ?? '/admin',
        'Logout' => $_SERVER['AUTH_PATH_LOGOUT'] ?? '/logout',
        'Assets' => $_SERVER['AUTH_ASSETS_PATH'] ?? '/assets',
    ];

    $isAdmin = ($_SERVER['HTTP_X_USER_ROLE'] ?? '') === 'admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Account</title>
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/style.css">
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/account.css">
</head>
<body>
    <div class="container content-container">
        <h2>My Account</h2>
        <p>Welcome, <?php echo htmlspecialchars($_SERVER['HTTP_X_USERNAME']); ?>!</p>
        <ul>
            <li><a href="<?php echo htmlspecialchars($paths['AccountPassword']); ?>">Change Password</a></li>
            <?php if ($isAdmin): ?>
                <li><a href="<?php echo htmlspecialchars($paths['Admin']); ?>">Admin Dashboard</a></li>
            <?php endif; ?>
        </ul>
        <section id="passkey-manager" hidden aria-labelledby="passkey-heading">
            <h2 id="passkey-heading">Passkeys</h2>
            <p>Sign in with your fingerprint, face or PIN. Keep your password to recover access if you lose your passkeys.</p>
            <ul id="passkey-list" aria-label="Registered passkeys"></ul>
            <form id="passkey-reauth-form">
                <label for="passkey-password">Current password</label>
                <input id="passkey-password" name="password" type="password" autocomplete="current-password" required>
                <p class="passkey-details">Verify again if your last sign-in was over five minutes ago.</p>
                <button type="submit" class="secondary-button">Verify identity</button>
            </form>
            <form id="passkey-add-form">
                <label for="passkey-name">Passkey name</label>
                <input id="passkey-name" name="name" type="text" autocomplete="off" placeholder="e.g. Personal phone" maxlength="100" required>
                <button type="submit">Add a passkey</button>
            </form>
            <p>Deleting a passkey signs you out on all devices and revokes API tokens.</p>
        </section>
        <p id="passkey-status" class="message" role="status" aria-live="polite"></p>
        <div class="logout-link">
            <a href="<?php echo htmlspecialchars($paths['Logout']); ?>">Logout</a>
        </div>
    </div>
    <script src="<?php echo htmlspecialchars($paths['Assets']); ?>/js/passkeys.js" defer></script>
</body>
</html>
