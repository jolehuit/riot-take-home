defmodule RiotTakeHome.Payload do
  @moduledoc """
  Depth-1 transformation of a JSON object's values.

  Each value is JSON-encoded before encryption, so its original type
  (number, object, array, boolean, null) is restored on decryption and the
  string `"30"` stays distinct from the number `30`.
  """

  alias RiotTakeHome.Cipher

  @doc "Encrypts every top-level value with the active cipher."
  @spec encrypt_payload(map()) :: map()
  def encrypt_payload(payload) when is_map(payload) do
    cipher = Cipher.active()

    Map.new(payload, fn {key, value} ->
      {key, Cipher.wrap(cipher, cipher.encrypt(JSON.encode!(value)))}
    end)
  end

  @doc """
  Decrypts every top-level value that carries a valid marker.

  A value is decrypted only if it is a string, starts with `enc:`, names a
  known cipher, and both decryption and JSON decoding succeed. Anything
  else comes back strictly unchanged.
  """
  @spec decrypt_payload(map()) :: map()
  def decrypt_payload(payload) when is_map(payload) do
    ciphers = Cipher.known()
    Map.new(payload, fn {key, value} -> {key, decrypt_value(value, ciphers)} end)
  end

  defp decrypt_value(value, ciphers) when is_binary(value) do
    with {:ok, id, data} <- Cipher.unwrap(value),
         {:ok, cipher} <- Map.fetch(ciphers, id),
         {:ok, plaintext} <- cipher.decrypt(data),
         {:ok, term} <- JSON.decode(plaintext) do
      term
    else
      _ -> value
    end
  end

  defp decrypt_value(value, _ciphers), do: value
end
