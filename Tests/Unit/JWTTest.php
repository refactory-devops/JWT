<?php
namespace RFY\JsonApi\Authenticator\Tests\Unit;

use TYPO3\Flow\Tests\UnitTestCase;
use RFY\JsonApi\Authenticator\JWT;

class JWTTest extends UnitTestCase {

	/**
	 * @test
	 */
	public function testEncodeDecode() {
		$msg = JWT::encode('abc', 'my_key');
		$this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), 'abc');
	}

	/**
	 * @test
	 */
	public function testDecodeFromPython() {
		$msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
		$this->assertEquals(
			JWT::decode($msg, 'my_key', array('HS256')),
			'*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
		);
	}

	/**
	 * @test
	 */
	public function testUrlSafeCharacters() {
		$encoded = JWT::encode('f?', 'a');
		$this->assertEquals('f?', JWT::decode($encoded, 'a', array('HS256')));
	}

	/**
	 * @test
	 */
	public function testMalformedUtf8StringsFail() {
		$this->setExpectedException('DomainException');
		JWT::encode(pack('c', 128), 'a');
	}

	/**
	 * @test
	 */
	public function testMalformedJsonThrowsException() {
		$this->setExpectedException('DomainException');
		JWT::jsonDecode('this is not valid JSON string');
	}

	/**
	 * @test
	 */
	public function testExpiredToken() {
		$this->setExpectedException('RFY\JsonApi\Authenticator\Exception\ExpiredException');
		$payload = array(
			"message" => "abc",
			"exp" => time() - 20); // time in the past
		$encoded = JWT::encode($payload, 'my_key');
		JWT::decode($encoded, 'my_key', array('HS256'));
	}

	/**
	 * @test
	 */
	public function testBeforeValidTokenWithNbf() {
		$this->setExpectedException('RFY\JsonApi\Authenticator\Exception\BeforeValidException');
		$payload = array(
			"message" => "abc",
			"nbf" => time() + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		JWT::decode($encoded, 'my_key', array('HS256'));
	}

	/**
	 * @test
	 */
	public function testBeforeValidTokenWithIat() {
		$this->setExpectedException('RFY\JsonApi\Authenticator\Exception\BeforeValidException');
		$payload = array(
			"message" => "abc",
			"iat" => time() + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		JWT::decode($encoded, 'my_key', array('HS256'));
	}

	/**
	 * @test
	 */
	public function testValidToken() {
		$payload = array(
			"message" => "abc",
			"exp" => time() + JWT::$leeway + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		$this->assertEquals($decoded->message, 'abc');
	}

	/**
	 * @test
	 */
	public function testValidTokenWithLeeway() {
		JWT::$leeway = 60;
		$payload = array(
			"message" => "abc",
			"exp" => time() - 20); // time in the past
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		$this->assertEquals($decoded->message, 'abc');
		JWT::$leeway = 0;
	}

	/**
	 * @test
	 */
	public function testExpiredTokenWithLeeway() {
		JWT::$leeway = 60;
		$payload = array(
			"message" => "abc",
			"exp" => time() - 70); // time far in the past
		$this->setExpectedException('RFY\JsonApi\Authenticator\Exception\ExpiredException');
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		$this->assertEquals($decoded->message, 'abc');
		JWT::$leeway = 0;
	}

	/**
	 * @test
	 */
	public function testValidTokenWithList() {
		$payload = array(
			"message" => "abc",
			"exp" => time() + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256', 'HS512'));
		$this->assertEquals($decoded->message, 'abc');
	}

	/**
	 * @test
	 */
	public function testValidTokenWithNbf() {
		$payload = array(
			"message" => "abc",
			"iat" => time(),
			"exp" => time() + 20, // time in the future
			"nbf" => time() - 20);
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		$this->assertEquals($decoded->message, 'abc');
	}

	/**
	 * @test
	 */
	public function testValidTokenWithNbfLeeway() {
		JWT::$leeway = 60;
		$payload = array(
			"message" => "abc",
			"nbf" => time() + 20); // not before in near (leeway) future
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		$this->assertEquals($decoded->message, 'abc');
		JWT::$leeway = 0;
	}

	/**
	 * @test
	 */
	public function testInvalidTokenWithNbfLeeway() {
		JWT::$leeway = 60;
		$payload = array(
			"message" => "abc",
			"nbf" => time() + 65); // not before too far in future
		$encoded = JWT::encode($payload, 'my_key');
		$this->setExpectedException('RFY\JsonApi\Authenticator\Exception\BeforeValidException');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		JWT::$leeway = 0;
	}

	/**
	 * @test
	 */
	public function testValidTokenWithIatLeeway() {
		JWT::$leeway = 60;
		$payload = array(
			"message" => "abc",
			"iat" => time() + 20); // issued in near (leeway) future
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		$this->assertEquals($decoded->message, 'abc');
		JWT::$leeway = 0;
	}

	/**
	 * @test
	 */
	public function testInvalidTokenWithIatLeeway() {
		JWT::$leeway = 60;
		$payload = array(
			"message" => "abc",
			"iat" => time() + 65); // issued too far in future
		$encoded = JWT::encode($payload, 'my_key');
		$this->setExpectedException('RFY\JsonApi\Authenticator\Exception\BeforeValidException');
		$decoded = JWT::decode($encoded, 'my_key', array('HS256'));
		JWT::$leeway = 0;
	}

	/**
	 * @test
	 */
	public function testInvalidToken() {
		$payload = array(
			"message" => "abc",
			"exp" => time() + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		$this->setExpectedException('RFY\JsonApi\Authenticator\Exception\SignatureInvalidException');
		$decoded = JWT::decode($encoded, 'my_key2', array('HS256'));
	}

	/**
	 * @test
	 */
	public function testNullKeyFails() {
		$payload = array(
			"message" => "abc",
			"exp" => time() + JWT::$leeway + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		$this->setExpectedException('InvalidArgumentException');
		$decoded = JWT::decode($encoded, null, array('HS256'));
	}

	/**
	 * @test
	 */
	public function testEmptyKeyFails() {
		$payload = array(
			"message" => "abc",
			"exp" => time() + JWT::$leeway + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		$this->setExpectedException('InvalidArgumentException');
		$decoded = JWT::decode($encoded, '', array('HS256'));
	}

	/**
	 * @test
	 */
	public function testRSEncodeDecode() {
		$privKey = openssl_pkey_new(array('digest_alg' => 'sha256',
			'private_key_bits' => 1024,
			'private_key_type' => OPENSSL_KEYTYPE_RSA));
		$msg = JWT::encode('abc', $privKey, 'RS256');
		$pubKey = openssl_pkey_get_details($privKey);
		$pubKey = $pubKey['key'];
		$decoded = JWT::decode($msg, $pubKey, array('RS256'));
		$this->assertEquals($decoded, 'abc');
	}

	/**
	 * @test
	 */
	public function testKIDChooser() {
		$keys = array('1' => 'my_key', '2' => 'my_key2');
		$msg = JWT::encode('abc', $keys['1'], 'HS256', '1');
		$decoded = JWT::decode($msg, $keys, array('HS256'));
		$this->assertEquals($decoded, 'abc');
	}

	/**
	 * @test
	 */
	public function testArrayAccessKIDChooser() {
		$keys = new \ArrayObject(array('1' => 'my_key', '2' => 'my_key2'));
		$msg = JWT::encode('abc', $keys['1'], 'HS256', '1');
		$decoded = JWT::decode($msg, $keys, array('HS256'));
		$this->assertEquals($decoded, 'abc');
	}

	/**
	 * @test
	 */
	public function testNoneAlgorithm() {
		$msg = JWT::encode('abc', 'my_key');
		$this->setExpectedException('DomainException');
		JWT::decode($msg, 'my_key', array('none'));
	}

	/**
	 * @test
	 */
	public function testIncorrectAlgorithm() {
		$msg = JWT::encode('abc', 'my_key');
		$this->setExpectedException('DomainException');
		JWT::decode($msg, 'my_key', array('RS256'));
	}

	/**
	 * @test
	 */
	public function testMissingAlgorithm() {
		$msg = JWT::encode('abc', 'my_key');
		$this->setExpectedException('DomainException');
		JWT::decode($msg, 'my_key');
	}

	/**
	 * @test
	 */
	public function testAdditionalHeaders() {
		$msg = JWT::encode('abc', 'my_key', 'HS256', null, array('cty' => 'test-eit;v=1'));
		$this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), 'abc');
	}

	/**
	 * @test
	 */
	public function testInvalidSegmentCount() {
		$this->setExpectedException('UnexpectedValueException');
		JWT::decode('brokenheader.brokenbody', 'my_key', array('HS256'));
	}
}