defmodule RiotTakeHome.Cipher.AesGcm do
  @moduledoc """
  AES-256-GCM with a fresh random 96-bit nonce per value.

  Output is `nonce <> tag <> ciphertext`, standard base64 with padding, so the
  same plaintext encrypts to a different string every time. Detection is
  cryptographic: `decrypt/1` opens the AEAD and lets tag verification decide,
  so a string this key never sealed fails authentication and reads as "not
  mine", without any marker on the wire.

  The key is the 32 bytes that `ENCRYPTION_KEY` carries base64-encoded,
  decoded and checked at boot in `config/runtime.exs`. It is distinct from the
  signing secret, since a value used to encrypt must not be the value used to
  sign. Base64 is the default cipher, so `ENCRYPTION_KEY` is only required
  when this one is active.
  """

  @behaviour RiotTakeHome.Cipher

  @nonce_size 12
  @tag_size 16

  @impl true
  def encrypt(plaintext) do
    # Only reached when this cipher is the configured one, so a missing key is
    # an operator error and failing loudly is right.
    key =
      case fetch_key() do
        {:ok, key} -> key
        :error -> raise "AES-256-GCM is the active cipher but ENCRYPTION_KEY is not set"
      end

    nonce = :crypto.strong_rand_bytes(@nonce_size)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, plaintext, "", true)

    Base.encode64(nonce <> tag <> ciphertext)
  end

  @impl true
  def decrypt(data) do
    # Reached for every string `/decrypt` inspects, so it must never raise: an
    # unconfigured key is just another reason this value cannot be decrypted,
    # and the caller leaves it untouched. The cheap structural check comes
    # first so a short or non-base64 value is rejected before any key handling.
    with {:ok, <<nonce::binary-size(@nonce_size), tag::binary-size(@tag_size), rest::binary>>} <-
           Base.decode64(data),
         {:ok, key} <- fetch_key(),
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, rest, "", tag, false) do
      {:ok, plaintext}
    else
      _ -> :error
    end
  end

  @spec fetch_key() :: {:ok, binary()} | :error
  defp fetch_key do
    case Application.fetch_env(:riot_take_home, :encryption_key) do
      {:ok, key} when is_binary(key) and byte_size(key) == 32 -> {:ok, key}
      _ -> :error
    end
  end
end
