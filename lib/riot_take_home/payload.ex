defmodule RiotTakeHome.Payload do
  @moduledoc """
  Depth-1 transformation of a JSON object's values.

  Each value is JSON-encoded before encryption, so its original type
  (number, object, array, boolean, null) is restored on decryption and the
  string `"30"` stays distinct from the number `30`.

  Detection on `/decrypt` is a heuristic, since nothing on the wire marks a
  ciphertext: a depth-1 string is replaced by its decoded value only when the
  active cipher accepts it (strict base64 for the default codec, the GCM tag
  for AES) and the plaintext is valid UTF-8 that decodes as JSON within the
  integer bound. Any condition failing returns the value byte for byte
  unchanged. The false positives this admits, strings like `"MzA="` that are
  valid base64 of valid JSON, are enumerated in the README and pinned in
  `payload_test.exs`.
  """

  alias RiotTakeHome.Bound
  alias RiotTakeHome.Cipher

  @doc "Encrypts every top-level value with the active cipher."
  @spec encrypt_payload(map()) :: map()
  def encrypt_payload(payload) when is_map(payload) do
    cipher = Cipher.active()
    Map.new(payload, fn {key, value} -> {key, cipher.encrypt(JSON.encode!(value))} end)
  end

  @doc """
  Decrypts every top-level value the active cipher recognises.

  Anything else, non-strings included, comes back strictly unchanged.
  """
  @spec decrypt_payload(map()) :: map()
  def decrypt_payload(payload) when is_map(payload) do
    cipher = Cipher.active()
    Map.new(payload, fn {key, value} -> {key, decrypt_value(cipher, value)} end)
  end

  # The bound check mirrors the router's: the request-side check only sees
  # integers that appear literally in the JSON, and a ciphertext hides its
  # plaintext from it, so what comes out of decryption is bounded here before
  # it can reach the response encoder (where an unbounded integer costs
  # seconds of CPU). A value past the bound is left as it arrived, exactly
  # like any other value that cannot be decrypted.
  defp decrypt_value(cipher, value) when is_binary(value) do
    with {:ok, plaintext} <- cipher.decrypt(value),
         true <- String.valid?(plaintext),
         {:ok, term} <- JSON.decode(plaintext),
         true <- Bound.bounded?(term) do
      term
    else
      _ -> value
    end
  end

  defp decrypt_value(_cipher, value), do: value
end
