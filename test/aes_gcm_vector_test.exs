defmodule RiotTakeHome.Cipher.AesGcmVectorTest do
  use ExUnit.Case, async: true

  alias RiotTakeHome.Cipher.AesGcm

  # Everything in this file was produced outside Elixir, with node's crypto
  # module, from the parameters this cipher documents: PBKDF2-HMAC-SHA256 over
  # the configured secret with the salt "riot_take_home/aes-256-gcm/v1" and
  # 600_000 iterations, then AES-256-GCM over a fixed nonce.
  #
  #   key   = crypto.pbkdf2Sync(secret, salt, 600000, 32, "sha256")
  #   c     = crypto.createCipheriv("aes-256-gcm", key, nonce)
  #   wire  = nonce || tag || ciphertext        (base64url, unpadded)
  #
  # The point is that nothing here can be satisfied by the code agreeing with
  # itself. A change to the nonce size, the salt, the iteration count, the hash,
  # the KDF, or the environment variable the key is read from all produce a
  # different key or a different layout, and this vector stops decrypting.
  @plaintext ~s({"n":1})
  @wire "AAECAwQFBgcICQoLePxL03WJi1UHiE1TDRu_abDmC4dK8vo"

  describe "decrypt/1" do
    test "decrypts a ciphertext produced entirely outside this codebase" do
      assert AesGcm.decrypt(@wire) == {:ok, @plaintext}
    end

    test "rejects the same vector with a flipped tag byte" do
      # byte 20 of the decoded wire sits inside the 16-byte tag
      <<head::binary-size(20), byte, rest::binary>> = Base.url_decode64!(@wire, padding: false)

      tampered =
        Base.url_encode64(<<head::binary, Bitwise.bxor(byte, 1), rest::binary>>, padding: false)

      assert AesGcm.decrypt(tampered) == :error
    end
  end

  describe "encrypt/1" do
    test "lays the wire out as nonce || tag || ciphertext, with a 12-byte nonce" do
      # GCM ciphertext is the same length as the plaintext, so the total pins
      # the nonce and tag sizes: shrink either one and this fails.
      decoded = @plaintext |> AesGcm.encrypt() |> Base.url_decode64!(padding: false)

      assert byte_size(decoded) == 12 + 16 + byte_size(@plaintext)
    end

    test "its own output decrypts under the externally derived key" do
      # Ties the encrypt side to the same key the external vector proves: the
      # nonce is random, so this cannot be pinned to a literal, but it can be
      # pinned to the vector's key by round-tripping through decrypt/1.
      assert AesGcm.decrypt(AesGcm.encrypt(@plaintext)) == {:ok, @plaintext}
    end
  end
end
