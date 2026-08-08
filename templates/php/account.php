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
        <div class="logout-link">
            <a href="<?php echo htmlspecialchars($paths['Logout']); ?>">Logout</a>
        </div>
    </div>
</body>
</html>
