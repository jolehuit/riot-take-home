defmodule RiotTakeHome.Signer do
  @moduledoc """
  Behaviour for a signature scheme over the canonical form.

  `verify/3` is a callback rather than re-sign-and-compare at the call
  site, so a scheme controls its own comparison (constant time here, and an
  asymmetric scheme could verify without ever recomputing the signature).
  """

  alias RiotTakeHome.Canonical

  @callback sign(message :: binary(), key :: binary()) :: String.t()
  @callback verify(message :: binary(), key :: binary(), signature :: String.t()) :: boolean()

  @doc "Signs a decoded JSON term with the configured scheme and secret."
  @spec sign(term()) :: String.t()
  def sign(data), do: active().sign(Canonical.encode(data), secret())

  @doc "Verifies a signature over a decoded JSON term. Non-string signatures are invalid."
  @spec valid?(term(), term()) :: boolean()
  def valid?(data, signature) when is_binary(signature) do
    active().verify(Canonical.encode(data), secret(), signature)
  end

  def valid?(_data, _signature), do: false

  defp active, do: Application.fetch_env!(:riot_take_home, :signer)
  defp secret, do: Application.fetch_env!(:riot_take_home, :signing_secret)
end
