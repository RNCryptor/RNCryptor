<?php
class RNCryptorTestCase extends PHPUnit_Framework_TestCase {

	const GOOD_PASSWORD = 'mypassword123$!';
	const BAD_PASSWORD = 'wrongpass';

	const PLAINTEXT = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...';

	const IOS_ENCRYPTED_V0 = 'AADu55As8qH9KsSR17p1akydMUlbHrsHudMOr/yTj4olfQedJPTZg8hK4ua99zNkj3Nw7Hle1f1onHclWIYoLkWtMVk4Cp96CcxRhaWbBZqAVvTabtVruxcAi+GEB2K4rrmyARxB2QJH9tfz2yTFoFNMln+xOCUm0wAAAAAAAAAAAAAAAA==';
	const IOS_ENCRYPTED_V1 = 'AQE9u3aB1APkWDRHcfy1cvD3kwwoXUw+8JhtCkZ3xDkSQghIyFoqLgazX3cXBxv3Mj75sSofHoDI35KaFTdXovY3HQYAaQmMdPNvSRVGvlptkyr5LSBMUA3/Uj7lmhnaf515pN8pUbcbOV8RP+oWhXX4iKN009mrcMaX2j1KQz2JfFj8bfpbu9BOtj+1NotIe14=';
	const IOS_ENCRYPTED_V2 = 'AgG8X+ixN6HN9zFnuK1NMJAPntIuC0+WPsmFhGL314zLuq1T9xWDHYzpnzW8EqDz81Amj36+EqrjazQ1gO9ao6bpMwUKdT2xY4ZUrhtCQm3LD2okbEIGjj5dtMJtB3i759WdnmNf8K0ULDWNzNQHPzdNDcEE2BPh+2kRaqVzWyBOzJppJoD5n+WdglS7BEBU+4U=';

}