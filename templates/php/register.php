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
    <title>Register</title>
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/style.css">
</head>
<body>
    <div class="container form-container">
        <h2>Create Account</h2>
        <form id="register-form" action="<?php echo htmlspecialchars($paths['Register']); ?>" method="post">
            <input type="hidden" name="xsrf_token" value="<?php echo htmlspecialchars($_SERVER['HTTP_X_XSRF_TOKEN']); ?>">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn-success">Register</button>
        </form>
        <p class="error">
            <?php
                if (!empty($_GET['error'])) {
                    echo htmlspecialchars($_GET['error']);
                }
            ?>
        </p>
        <div class="form-link">
            <a href="<?php echo htmlspecialchars($paths['Login']); ?>">Already have an account? Login</a>
        </div>
    </div>
</body>
</html>