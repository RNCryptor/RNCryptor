# encoding: utf-8

require File.join(File.dirname(__FILE__), '../lib/ruby_rncryptor.rb')

describe RubyRNCryptor do

	before :each do
		@plain_text = "Hello, World! Let's use a few blocks with a longer sentence."
		@password = "P@ssw0rd!"
	end

	it "Decrypts v2 data with password" do
		encrypted_data = ["02013F194AA9969CF70C8ACB76824DE4CB6CDCF78B7449A87C679FB8EDB6A0109C513481DE877F3A855A184C4947F2B3E8FEF7E916E4739F9F889A717FCAF277402866341008A09FD3EBAC7FA26C969DD7EE72CFB695547C971A75D8BF1CC5980E0C727BD9F97F6B7489F687813BEB94DEB61031260C246B9B0A78C2A52017AA8C92"].pack('H*')
		decrypted = RubyRNCryptor.decrypt(encrypted_data, @password)
		decrypted.should == @plain_text
	end
	
	it "Decrypts v3 data with password" do
		encrypted_data = ["0301835b93e734143340ca8b55fc77865be906abe119073b77d5bc461fcc8bc8aea42fde3eb01b33bd3b54f2d58aaaef7747d24e1bde83aab5f81d7e68e3e2ba6c4f1420b638faea3d6dec7c801345d5bc059289f52b4d030786fc11e22a3939efd7c88a6cad3e23a9fc87e6bbfbc38901525b2ef7384045923260b3928a5bedbf7b"].pack('H*')
		decrypted = RubyRNCryptor.decrypt(encrypted_data, @password)
		decrypted.should == @plain_text
	end
	
	it "Decrypts sample v2 data with truncated password" do
		encrypted_data = ["0201ce29ed6bca00cf0c39390c1227284443f39133a35100539ba3f8fc84cf6da8d9db450233f2689858de35b40570f85bd2f81a70218ac72bf0f299fb33b35836d3141dffe9a96fd8b590d53086e1ca53d2"].pack('H*')
		decrypted = RubyRNCryptor.decrypt(encrypted_data, "中文密码")
		decrypted.should == "Attack at dawn"
	end

	it "Encrypt with password should decrypt" do
		encrypted = RubyRNCryptor.encrypt(@plain_text, @password)
		RubyRNCryptor.decrypt(encrypted, @password).should == @plain_text
	end
	
	it "Encrypts and decrypts larger blocks of data" do
		bigger_data = OpenSSL::Random.random_bytes(4043)
		encrypted = RubyRNCryptor.encrypt(bigger_data, @password)
		RubyRNCryptor.decrypt(encrypted, @password).should == bigger_data
	end

	it "Fails to decrypt when wrong password is used" do
		encrypted = RubyRNCryptor.encrypt(@plain_text, @password)
		expect { RubyRNCryptor.decrypt(encrypted, "WRONG") }.to raise_error
	end
	
	it "Raises an error when unsupported file format versions are requested" do
		expect { RubyRNCryptor.encrypt(@plain_text, @password, 1) }.to raise_error
	end
	
	it "Should properly encrypt and decrypt multibyte passwords in v2" do
		encrypted = RubyRNCryptor.encrypt(@plain_text, "中文密码", 2)
		RubyRNCryptor.decrypt(encrypted, "中文密码").should == @plain_text
	end

	it "Should properly encrypt and decrypt multibyte passwords in v3" do
		encrypted = RubyRNCryptor.encrypt(@plain_text, "中文密码")	# default to v3
		RubyRNCryptor.decrypt(encrypted, "中文密码").should == @plain_text
	end

	it "Should properly decrypt truncated multibyte passwords generated in Cocoa v2 format" do
		# This works around a bug in the Cocoa version where the password string was truncated
		# a string to the first x bytes where x is the number of multibyte characters in the string.
		
		encrypted = RubyRNCryptor.encrypt(@plain_text, RubyRNCryptor.truncate_multibyte_password("中文密码"), 2)
		RubyRNCryptor.decrypt(encrypted, "中文中文").should == @plain_text
	end
	
	it "Should fail to decrypt v3 format multibyte passwords." do
		encrypted = RubyRNCryptor.encrypt(@plain_text, "中文密码")	# default to v3
		expect { RubyRNCryptor.decrypt(encrypted, "中文中文") }.to raise_error
	end
		
end
