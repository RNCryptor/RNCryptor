require File.join(File.dirname(__FILE__), '../lib/ruby_rncryptor.rb')

describe RubyRNCryptor do

  before :each do
    @plain_text = "Hello, World! Let's use a few blocks with a longer sentence."
    @encrypted_data = ["02013F194AA9969CF70C8ACB76824DE4CB6CDCF78B7449A87C679FB8EDB6A0109C513481DE877F3A855A184C4947F2B3E8FEF7E916E4739F9F889A717FCAF277402866341008A09FD3EBAC7FA26C969DD7EE72CFB695547C971A75D8BF1CC5980E0C727BD9F97F6B7489F687813BEB94DEB61031260C246B9B0A78C2A52017AA8C92"].pack('H*')
    @password = "P@ssw0rd!"
  end

  it "Decrypt with password" do
    decrypted = RubyRNCryptor.decrypt(@encrypted_data, @password)
    decrypted.should == @plain_text
  end

  it "Encrypt with password should decrypt" do
    encrypted = RubyRNCryptor.encrypt(@plain_text, @password)
    RubyRNCryptor.decrypt(encrypted, @password).should == @plain_text
  end
  
  it "Encrypt lots of data with password and it should decrypt" do
    bigger_data = OpenSSL::Random.random_bytes(4043)
    encrypted = RubyRNCryptor.encrypt(bigger_data, @password)
    RubyRNCryptor.decrypt(encrypted, @password).should == bigger_data
  end

  it "Decrypt with wrong password should result in an error" do
    encrypted = RubyRNCryptor.encrypt(@plain_text, @password)
    expect { RubyRNCryptor.decrypt(encrypted, "WRONG") }.to raise_error
  end
  
end
