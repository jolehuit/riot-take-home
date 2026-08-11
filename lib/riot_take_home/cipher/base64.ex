defmodule RiotTakeHome.Cipher.Base64 do
  @moduledoc """
  Url-safe base64 codec, no padding, strict decoding.

  Encoding rather than encryption; the marker makes that an explicit,
  swappable choice instead of a hidden one.
  """

  @behaviour RiotTakeHome.Cipher

  @impl true
  def id, do: "b64"

  @impl true
  def encrypt(plaintext), do: Base.url_encode64(plaintext, padding: false)

  @impl true
  def decrypt(data) do
    # `padding: false` alone tolerates padded input; "=" never occurs in the
    # unpadded url-safe alphabet, so its presence is rejected outright.
    if String.contains?(data, "="), do: :error, else: Base.url_decode64(data, padding: false)
  end
end
