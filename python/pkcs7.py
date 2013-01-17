import binascii
import StringIO

'''
	http://japrogbits.blogspot.com/2011/02/using-encrypted-data-between-python-and.html
'''

class PKCS7Encoder(object):
	'''
	RFC 2315: PKCS#7 page 21
	Some content-encryption algorithms assume the
	input length is a multiple of k octets, where k > 1, and
	let the application define a method for handling inputs
	whose lengths are not a multiple of k octets. For such
	algorithms, the method shall be to pad the input at the
	trailing end with k - (l mod k) octets all having value k -
	(l mod k), where l is the length of the input. In other
	words, the input is padded at the trailing end with one of
	the following strings:

	         01 -- if l mod k = k-1
	        02 02 -- if l mod k = k-2
	                    .
	                    .
	                    .
	      k k ... k k -- if l mod k = 0

	The padding can be removed unambiguously since all input is
	padded and no padding string is a suffix of another. This
	padding method is well-defined if and only if k < 256;
	methods for larger k are an open issue for further study.
	'''
	def __init__(self, k=16):
		self.k = k

	## @param text The padded text for which the padding is to be removed.
	# @exception ValueError Raised when the input padding is missing or corrupt.
	def decode(self, text):
		'''
		Remove the PKCS#7 padding from a text string
		'''
		nl = len(text)
		val = int(binascii.hexlify(text[-1]), 16)
		if val > self.k:
		    raise ValueError('Input is not padded or padding is corrupt')

		l = nl - val
		return text[:l]

	## @param text The text to encode.
	def encode(self, text):
		'''
		Pad an input string according to PKCS#7
		'''
		l = len(text)
		output = StringIO.StringIO()
		val = self.k - (l % self.k)
		for _ in xrange(val):
		    output.write('%02x' % val)
		return text + binascii.unhexlify(output.getvalue())
