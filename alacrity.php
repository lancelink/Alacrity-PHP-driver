<?php

/**
* Alacrity PHP Driver
* A php websocket driver for Alacrity `https://github.com/Cipherwraith/alacrity`
*
* @author Lance Link <lance@bytesec.org>
* @author Fredrick Brennan <copypaste@kittens.ph>
**/

class AlacrityException extends Exception {};
class Alacrity {
	private $connected = false;
	private $password = "u2HZxn3LX4aRLZpX";

	function __construct($host, $port) {
		$this->host = $host;
		$this->port = $port;
	}

	function Connect() {
		$head = "GET / HTTP/1.1"."\r\n";
		$head .= "Upgrade: WebSocket"."\r\n";
		$head .= "Connection: Upgrade"."\r\n";
		$head .= "Host: $this->host"."\r\n";
		$head .= "Sec-WebSocket-Version: 13"."\r\n";
		$head .= "Sec-WebSocket-Key: LnIpBswFNVqwlPmLElCjE4yhl"."\r\n";
		$head .= "Content-Length: 0\r\n\r\n";
		$errno = $errstr = NULL;
		$this->sock = fsockopen($this->host, $this->port, $errno, $errstr, 5);

		if (!$this->sock) throw new AlacrityException("Could not connect to alacrity. fsockopen call failed with code $errno and message \"$errstr\"");
		
		//WebSocket handshake
		$ret = fwrite($this->sock, $head);
		if (!$ret) throw new AlacrityException("Could not send websocket header to alacrity");
		$headers = fread($this->sock, 2000);
		if (!$headers) throw new AlacrityException("Alacrity returned no headers");
		
		if($this->sock) {
			$this->connected = true;
		}
		return $this->sock;
	}

	function Store($data, $path) {
		$cmd_data = array("command" => "store", "data" => base64_encode($data), "path" => $path, "password" => $this->password);
		$ret = $this->ServerCall(json_encode($cmd_data));
		$retj = json_decode($ret, true);
		if (in_array("error", $retj)) {
			throw new AlacrityException("Store command failed. Alacrity response: $ret");
		} else {
			return $retj;
		}
	}

	function View($path) {
		$cmd_data = array("command" => "view", "path" => $path, "password" => $this->password);
		$ret = $this->ServerCall(json_encode($cmd_data));
		$retj = json_decode($ret, true);
		if (in_array("error", $retj)) {
			throw new AlacrityException("Store command failed. Alacrity response: $ret");
		} else {
			$retj['view'] = base64_decode($retj['view']);
			return $retj;
		}
	}

	function ViewRaw($path) {
		$cmd_data = array("command" => "viewraw", "path" => $path, "password" => $this->password);
		$ret = $this->ServerCall(json_encode($cmd_data));
		return $ret;
	}

	function Close() {
		fclose($this->sock);
		$this->connected = false;
	}

	function ServerCall($data) {
		if(!$this->connected)
			throw new AlacrityException('Not connected');
		// Send data
		$retr = fwrite($this->sock, $this->_hybi10Encode($data));
	
		if (!$retr) throw new AlacrityException("Could not send websocket header to alacrity");

		$wsdata = '';
		$dyread = '';
		while (1) {
			$dyread = fread($this->sock, 2048);
			$tmp = substr($this->_hybi10Decode($dyread)['payload'], -5); // Detect the `BREAK` (EOF) of Alacrity response
			if($tmp != "BREAK") {
				$wsdata .= $dyread;
			} else {
				$dyread = substr($dyread, 0, -9); // Removes the `BREAK` (EOF) of Alacrity response from the last chunk of data and append to data pool
				$wsdata .= $dyread;
				break;
			}
		}

		if (!$wsdata) throw new AlacrityException("Received an empty reply from alacrity");

		return $this->_hybi10Decode($wsdata)['payload'];
	}

	private function _hybi10Decode($data) {
		$payloadLength 		= '';
		$mask 			= '';
		$unmaskedPayload 	= '';
		$decodedData 		= array();

		$firstByteBinary 	= sprintf('%08b', ord($data[0]));		
		$secondByteBinary 	= sprintf('%08b', ord($data[1]));
		$opcode 		= bindec(substr($firstByteBinary, 4, 4));
		$isMasked 		= ($secondByteBinary[0] == '1') ? true : false;
		$payloadLength 		= ord($data[1]) & 127;

		$decodedData['type'] = 'text';

		if($payloadLength === 126) {
		   $mask = substr($data, 4, 4);
		   $payloadOffset = 8;
		   $dataLength = bindec(sprintf('%08b', ord($data[2])) . sprintf('%08b', ord($data[3]))) + $payloadOffset;
		} elseif($payloadLength === 127) {
			$mask = substr($data, 10, 4);
			$payloadOffset = 14;
			$tmp = '';
			for($i = 0; $i < 8; $i++) {
				$tmp .= sprintf('%08b', ord($data[$i+2]));
			}
			$dataLength = bindec($tmp) + $payloadOffset;
			unset($tmp);
		} else {
			$mask = substr($data, 2, 4);	
			$payloadOffset = 6;
			$dataLength = $payloadLength + $payloadOffset;
		}	
		
		if($isMasked === true) {
			for($i = $payloadOffset; $i < $dataLength; $i++) {
				$j = $i - $payloadOffset;
				if(isset($data[$i])) {
					$unmaskedPayload .= $data[$i] ^ $mask[$j % 4];
				}
			}
			$decodedData['payload'] = $unmaskedPayload;
		} else {
			$payloadOffset = $payloadOffset - 4;
			$decodedData['payload'] = substr($data, $payloadOffset);
		}
		return $decodedData;
	}

	private function _hybi10Encode($payload, $type = 'text', $masked = true) {
		$frameHead = array();
		$frame = '';
		$payloadLength = strlen($payload);
		
		// Type text always - Lance
		// first byte indicates FIN, Text-Frame (10000001):
		$frameHead[0] = 129;	
		
		// set mask and payload length (using 1, 3 or 9 bytes) 
		if($payloadLength > 65535) {
			$payloadLengthBin = str_split(sprintf('%064b', $payloadLength), 8);
			$frameHead[1] = ($masked === true) ? 255 : 127;
			for($i = 0; $i < 8; $i++) {
				$frameHead[$i+2] = bindec($payloadLengthBin[$i]);
			}
			// most significant bit MUST be 0 (close connection if frame too big)
			if($frameHead[2] > 127) {
				$this->close(1004);
				return false;
			}
		} elseif($payloadLength > 125) {
			$payloadLengthBin = str_split(sprintf('%016b', $payloadLength), 8);
			$frameHead[1] = ($masked === true) ? 254 : 126;
			$frameHead[2] = bindec($payloadLengthBin[0]);
			$frameHead[3] = bindec($payloadLengthBin[1]);
		} else {
			$frameHead[1] = ($masked === true) ? $payloadLength + 128 : $payloadLength;
		}

		// convert frame-head to string:
		foreach(array_keys($frameHead) as $i) {
			$frameHead[$i] = chr($frameHead[$i]);
		}
		if($masked === true) {
			// generate a random mask:
			$mask = array();
			for($i = 0; $i < 4; $i++) {
				$mask[$i] = chr(rand(0, 255));
			}
			$frameHead = array_merge($frameHead, $mask);			
		}						
		$frame = implode('', $frameHead);

		// append payload to frame:
		$framePayload = array();	
		for($i = 0; $i < $payloadLength; $i++) {
			$frame .= ($masked === true) ? $payload[$i] ^ $mask[$i % 4] : $payload[$i];
		}
		return $frame;
	}
}
?>
