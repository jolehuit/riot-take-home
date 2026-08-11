defmodule RiotTakeHome.Signer.HmacSha256 do
  @moduledoc "HMAC-SHA256 signer. The active scheme; body in `RiotTakeHome.Signer.Hmac`."

  @behaviour RiotTakeHome.Signer

  alias RiotTakeHome.Signer.Hmac

  @impl true
  def sign(message, key), do: Hmac.sign(:sha256, message, key)

  @impl true
  def verify(message, key, signature), do: Hmac.verify(:sha256, message, key, signature)
end
