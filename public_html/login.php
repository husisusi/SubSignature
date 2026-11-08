<?php
// login.php - legacy entry point. The old single-password admin login was
// removed (hard-coded "admin" account, no rate limit); everything goes through index.php.
header('Location: index.php', true, 301);
exit;
