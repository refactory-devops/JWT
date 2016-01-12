<?php
namespace RFY\JWT\RequestPattern;

use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Mvc\RequestInterface;
use TYPO3\Flow\Security\RequestPatternInterface;

/**
 *
 */
class SkipOptionRequests implements RequestPatternInterface {

	/**
	 * @var array
	 */
	protected $skipMethodsPattern = array();

	/**
	 * Returns the set pattern
	 *
	 * @return array The set pattern
	 */
	public function getPattern() {
		return $this->skipMethodsPattern;
	}

	/**
	 * @param object $skipMethodsPattern
	 */
	public function setPattern($skipMethodsPattern) {
		$this->skipMethodsPattern = $skipMethodsPattern;
	}

	/**
	 * Matches a \TYPO3\Flow\Mvc\RequestInterface against its set controller object name pattern rules
	 *
	 * @param \TYPO3\Flow\Mvc\RequestInterface $request The request that should be matched
	 * @return boolean TRUE if the pattern matched, FALSE otherwise
	 */
	public function matchRequest(RequestInterface $request) {
		if (!$request instanceof ActionRequest) {
			return FALSE;
		}

		foreach ($this->getPattern() as $method) {
			if ($request->getHttpRequest()->getMethod() === $method) {
				return TRUE;
			}
		}
	}
}
