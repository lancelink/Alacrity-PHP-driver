# Alacrity-PHP-driver
PHP websocket driver for [Alacrity] (https://github.com/Cipherwraith/alacrity)

### Alacrity client example
```php
require('alacrity.php');

$alacrity = new Alacrity(ALACRITY_SERVER_IP, ALACRITY_PORT); // Initialize alacrity object

$alacrity->Connect(); // Connect to alacrity

$store_response = $alacrity->Store("data_here", "/path/tofile.html"); // store data to path
$view_response  = $alacrity->View("/path/tofile.html"); // view json data by path
$raw_view_response  = $alacrity->ViewRaw("/path/tofile.html"); // view plain text data by path

$alacrity->Close(); // Disconnect alacrity
```
