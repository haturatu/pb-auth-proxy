<?php
    $paths = [
        'Login' => $_SERVER['AUTH_PATH_LOGIN'] ?? '/login',
        'Register' => $_SERVER['AUTH_PATH_REGISTER'] ?? '/register',
        'Assets' => $_SERVER['AUTH_ASSETS_PATH'] ?? '/assets',
    ];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/style.css">
</head>
<body>
    <div class="container form-container">
        <h2>Login Required</h2>
        <form id="login-form" action="<?php echo htmlspecialchars($paths['Login']); ?>" method="post">
            <input type="hidden" name="xsrf_token" value="<?php echo htmlspecialchars($_SERVER['HTTP_X_XSRF_TOKEN']); ?>">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" autocomplete="username webauthn" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" autocomplete="current-password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <section id="passkey-signin" hidden aria-label="Passkey sign in">
            <p class="passkey-divider">or</p>
            <button type="button" id="passkey-login">Sign in with a passkey</button>
            <p class="passkey-details">Use your fingerprint, face or PIN.</p>
        </section>
        <p id="passkey-status" class="message" role="status" aria-live="polite"></p>
        <p class="error">
            <?php
                if (!empty($_GET['error'])) {
                    echo htmlspecialchars($_GET['error']);
                }
            ?>
        </p>
        <div style="text-align: center; margin-top: 1rem;">
            <a href="<?php echo htmlspecialchars($paths['Register']); ?>">Don't have an account? Register</a>
        </div>
    </div>
    <script src="<?php echo htmlspecialchars($paths['Assets']); ?>/js/passkeys.js" defer></script>
</body>
</html>