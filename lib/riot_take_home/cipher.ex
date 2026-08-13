defmodule RiotTakeHome.Cipher do
  @moduledoc """
  Behaviour for a reversible value cipher.

  `decrypt/1` doubles as detection: nothing on the wire marks a ciphertext,
  so each algorithm decides for itself whether a string is one of its own and
  returns `:error` for anything that is not. Base64 lets the strict decode
  decide; AES-GCM lets the authentication tag decide. The caller treats
  `:error` as "not encrypted" and passes the value through unchanged.
  """

  @callback encrypt(plaintext :: binary()) :: binary()
  @callback decrypt(data :: binary()) :: {:ok, binary()} | :error

  @doc "The cipher `/encrypt` and `/decrypt` use, resolved from application config."
  @spec active() :: module()
  def active, do: Application.fetch_env!(:riot_take_home, :cipher)
end
