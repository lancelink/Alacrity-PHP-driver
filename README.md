# Alacrity-PHP-driver
PHP websocket driver for alacrity

# Alacrity client example
```php
require('alacrity.php');

$alacrity = new Alacrity(ALACRITY_SERVER_IP, ALACRITY_PORT);
$store_response = $alacrity->Store("data_here", "/path/tofile.html"); // store data to path
$view_response  = $alacrity->View("/path/tofile.html"); // view data by path
```

