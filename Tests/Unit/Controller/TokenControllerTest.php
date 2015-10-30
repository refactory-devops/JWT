<?php
namespace RFY\JsonApi\Authenticator\Tests\Unit\Controller;

use TYPO3\Flow\Tests\UnitTestCase;

class TokenControllerTest extends UnitTestCase {

	/**
	 * @test
	 */
	public function testIfAnFlashMessageAndRedirectAreExecutedOnException() {
//		$tokenControllerMock = $this->getAccessibleMock('RFY\JsonApi\Authenticator\Controller\TokenController', ['dummy'], [], '', false);
//
//		$authenticationManagerMock = $this->getMock('TYPO3\Flow\Security\Authentication\AuthenticationProviderManager', [], [], '', false);
//
//		$this->inject($tokenControllerMock, 'authenticationManager', $authenticationManagerMock);
////
////		$exception = new \Exception();
//////		$authenticationManagerMock->expects($this->once())->method('authenticate')->willThrowException($exception);
////
////		$tokenControllerMock->expects($this->once())->method('addFlashMessage');
////
////		$tokenControllerMock->expects($this->once())->method('forwardToReferringRequest');
//
//		$this->assertNull($tokenControllerMock->authenticateAction());
	}
}