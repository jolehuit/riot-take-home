defmodule RiotTakeHome.Signer.Hmac do
  @moduledoc """
  Shared HMAC body for the `RiotTakeHome.Signer` implementations.

  The scheme differs only by hash function, so the signing and the
  constant-time verification live here once and each scheme module supplies its
  `:sha256` / `:sha512` atom. Signatures are lowercase hex.
  """

  @doc "Signs `message` with `algo` (a `:crypto` hash) and `key`."
  @spec sign(atom(), binary(), binary()) :: String.t()
  def sign(algo, message, key) do
    :hmac
    |> :crypto.mac(algo, key, message)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Recomputes the signature and compares in constant time. The size guard comes
  first because `:crypto.hash_equals/2` raises when the two binaries differ in
  length, which also rejects a signature made with the other hash on sight.
  """
  @spec verify(atom(), binary(), binary(), String.t()) :: boolean()
  def verify(algo, message, key, signature) do
    expected = sign(algo, message, key)
    byte_size(expected) == byte_size(signature) and :crypto.hash_equals(expected, signature)
  end
end
