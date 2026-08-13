defmodule RiotTakeHome.Cipher.AesGcmVectorTest do
  use ExUnit.Case, async: true

  alias RiotTakeHome.Cipher.AesGcm

  # Everything in this file was produced outside Elixir, with node's crypto
  # module, under the key config/test.exs configures (the 32 bytes 0x00..0x1f)
  # and a fixed nonce (the 12 bytes 0x00..0x0b):
  #
  #   key   = Buffer.from("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "base64")
  #   nonce = Buffer.from("000102030405060708090a0b", "hex")
  #   c     = crypto.createCipheriv("aes-256-gcm", key, nonce)
  #   ct    = Buffer.concat([c.update('{"n":1}'), c.final()])
  #   wire  = Buffer.concat([nonce, c.getAuthTag(), ct]).toString("base64")
  #
  # The point is that nothing here can be satisfied by the code agreeing with
  # itself. A change to the nonce size, the wire layout, the base64 alphabet,
  # or the variable the key is read from all make this vector stop decrypting.
  @plaintext ~s({"n":1})
  @wire "AAECAwQFBgcICQoLnC7+pk5gtDf6uERqsDtuOzwguDn/1L8="

  describe "decrypt/1" do
    test "decrypts a ciphertext produced entirely outside this codebase" do
      assert AesGcm.decrypt(@wire) == {:ok, @plaintext}
    end

    test "rejects the same vector with a flipped tag byte" do
      # byte 20 of the decoded wire sits inside the 16-byte tag
      <<head::binary-size(20), byte, rest::binary>> = Base.decode64!(@wire)

      tampered = Base.encode64(<<head::binary, Bitwise.bxor(byte, 1), rest::binary>>)

      assert AesGcm.decrypt(tampered) == :error
    end
  end

  describe "encrypt/1" do
    test "lays the wire out as nonce || tag || ciphertext, with a 12-byte nonce" do
      # GCM ciphertext is the same length as the plaintext, so the total pins
      # the nonce and tag sizes: shrink either one and this fails.
      decoded = @plaintext |> AesGcm.encrypt() |> Base.decode64!()

      assert byte_size(decoded) == 12 + 16 + byte_size(@plaintext)
    end

    test "its own output decrypts under the key the external vector proves" do
      # Ties the encrypt side to that same key: the nonce is random, so this
      # cannot be pinned to a literal, but it can be pinned to the vector's key
      # by round-tripping through decrypt/1.
      assert AesGcm.decrypt(AesGcm.encrypt(@plaintext)) == {:ok, @plaintext}
    end
  end
end
