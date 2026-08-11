defmodule RiotTakeHome.Signer.HmacSha512 do
  @moduledoc """
  HMAC-SHA512 signer. Second implementation of the behaviour, so the swap
  (`config :riot_take_home, :signer`) is exercised for signatures the way the
  second cipher exercises it for encryption. Body in `RiotTakeHome.Signer.Hmac`.
  """

  @behaviour RiotTakeHome.Signer

  alias RiotTakeHome.Signer.Hmac

  @impl true
  def sign(message, key), do: Hmac.sign(:sha512, message, key)

  @impl true
  def verify(message, key, signature), do: Hmac.verify(:sha512, message, key, signature)
end
