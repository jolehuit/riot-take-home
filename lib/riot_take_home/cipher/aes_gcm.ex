defmodule RiotTakeHome.Cipher.AesGcm do
  @moduledoc """
  AES-256-GCM with a fresh random 96-bit nonce per value.

  Output is `nonce <> tag <> ciphertext`, url-safe base64 without padding, so
  the same plaintext encrypts to a different marker every time. The 32-byte key
  is derived from a dedicated `ENCRYPTION_KEY` with PBKDF2 (RFC 8018) via the
  OTP-native `:crypto.pbkdf2_hmac/5`, rather than a bare hash, with a fixed salt
  for domain separation. The key is distinct from the signing secret, since a
  value used to encrypt must not be the value used to sign. Base64 is the
  default cipher, so `ENCRYPTION_KEY` is only required when this one is active.
  """

  @behaviour RiotTakeHome.Cipher

  @nonce_size 12
  @tag_size 16

  @impl true
  def id, do: "aesgcm"

  @impl true
  def encrypt(plaintext) do
    nonce = :crypto.strong_rand_bytes(@nonce_size)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key(), nonce, plaintext, "", true)

    Base.url_encode64(nonce <> tag <> ciphertext, padding: false)
  end

  @impl true
  def decrypt(data) do
    with {:ok, <<nonce::binary-size(@nonce_size), tag::binary-size(@tag_size), rest::binary>>} <-
           Base.url_decode64(data, padding: false),
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(:aes_256_gcm, key(), nonce, rest, "", tag, false) do
      {:ok, plaintext}
    else
      _ -> :error
    end
  end

  @kdf_salt "riot_take_home/aes-256-gcm/v1"

  defp key do
    case Application.fetch_env(:riot_take_home, :encryption_secret) do
      {:ok, secret} when is_binary(secret) and secret != "" ->
        # PBKDF2-HMAC-SHA256 (RFC 8018), 1000 iterations, 32-byte key. The input
        # is a high-entropy secret, not a password, so the iteration count is not
        # the security parameter here; the salt gives domain separation from any
        # other key derived from the same secret.
        :crypto.pbkdf2_hmac(:sha256, secret, @kdf_salt, 1000, 32)

      _ ->
        raise "AES-256-GCM is the active cipher but ENCRYPTION_KEY is not set"
    end
  end
end
