<?php
    $paths = [
        'Account' => $_SERVER['AUTH_PATH_ACCOUNT'] ?? '/account',
        'AccountPassword' => $_SERVER['AUTH_PATH_ACCOUNT_PASSWORD'] ?? '/account/password',
        'Assets' => $_SERVER['AUTH_ASSETS_PATH'] ?? '/assets',
    ];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password</title>
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/style.css">
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/account.css">
</head>
<body>
    <div class="container content-container">
        <h2>Change Password</h2>
        <form id="change-password-form" action="<?php echo htmlspecialchars($paths['AccountPassword']); ?>" method="post">
            <input type="hidden" name="xsrf_token" value="<?php echo htmlspecialchars($_SERVER['HTTP_X_XSRF_TOKEN']); ?>">
            <div class="form-group">
                <label for="current_password">Current Password</label>
                <input type="password" id="current_password" name="current_password" required>
            </div>
            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password" required>
            </div>
            <div class="form-group">
                <label for="confirm_new_password">Confirm New Password</label>
                <input type="password" id="confirm_new_password" name="confirm_new_password" required>
            </div>
            <button type="submit">Update Password</button>
        </form>
        <p id="message-placeholder" class="message"></p>
        <div class="back-link">
            <a href="<?php echo htmlspecialchars($paths['Account']); ?>">Back to Account</a>
        </div>
    </div>
    <script src="<?php echo htmlspecialchars($paths['Assets']); ?>/js/auth.js"></script>
</body>
</html>