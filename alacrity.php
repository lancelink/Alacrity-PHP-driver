<?php

class Alacrity {

	function __construct($host, $port) {
		$this->host = $host;
		$this->port = $port;
	}
	
	function Store($data, $path) {
		$cmd_data = '{"command":"store", "data":"'.$data.'", "path":"'.$path.'"}';
		return $this->ServerCall($cmd_data);
	}

	function View($path) {
		$cmd_data = '{"command":"view", "path":"'.$path.'"}';
		return $this->ServerCall($cmd_data);
	}

	function ServerCall($data) {
		$head = "GET / HTTP/1.1"."\r\n";
		$head .= "Upgrade: WebSocket"."\r\n";
		$head .= "Connection: Upgrade"."\r\n";
		$head .= "Host: $this->host"."\r\n";
		$head .= "Sec-WebSocket-Version: 13"."\r\n";
		$head .= "Sec-WebSocket-Key: LnIpBswFNVqwlPmLElCjE4yhl"."\r\n";
		$head .= "Content-Length: ".strlen($data)."\r\n"."\r\n";
		//WebSocket handshake
		$sock = fsockopen($this->host, $this->port, $errno, $errstr, 2);
		fwrite($sock, $head ) or die('error:'.$errno.':'.$errstr);
		$headers = fread($sock, 2000);
		fwrite($sock, $this->_hybi10Encode($data)) or die('error:'.$errno.':'.$errstr);
		$wsdata = fread($sock, 2000);
		fclose($sock);

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
