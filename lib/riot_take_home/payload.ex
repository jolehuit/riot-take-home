defmodule RiotTakeHome.Payload do
  @moduledoc """
  Depth-1 transformation of a JSON object's values.

  Each value is JSON-encoded before encryption, so its original type
  (number, object, array, boolean, null) is restored on decryption and the
  string `"30"` stays distinct from the number `30`.
  """

  alias RiotTakeHome.Bound
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

  # The bound check mirrors the router's: the request-side check only sees
  # integers that appear literally in the JSON, and a ciphertext hides its
  # plaintext from it, so what comes out of decryption is bounded here before
  # it can reach the response encoder (where an unbounded integer costs
  # seconds of CPU). A value past the bound is left as it arrived, exactly
  # like any other value that cannot be decrypted.
  defp decrypt_value(value, ciphers) when is_binary(value) do
    with {:ok, id, data} <- Cipher.unwrap(value),
         {:ok, cipher} <- Map.fetch(ciphers, id),
         {:ok, plaintext} <- cipher.decrypt(data),
         {:ok, term} <- JSON.decode(plaintext),
         true <- Bound.bounded?(term) do
      term
    else
      _ -> value
    end
  end

  defp decrypt_value(value, _ciphers), do: value
end
