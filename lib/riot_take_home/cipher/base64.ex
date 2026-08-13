defmodule RiotTakeHome.Cipher.Base64 do
  @moduledoc """
  Standard base64 with padding, the algorithm the assignment names.

  Encoding rather than encryption, so `decrypt/1` is the strict decode:
  `Base.decode64/1` rejects any character outside the standard alphabet and
  any missing or misplaced padding, and that rejection is this algorithm's
  whole detection step. Whether the decoded bytes are a plausible plaintext
  (valid UTF-8, valid JSON, bounded integers) is the caller's judgment, not
  the codec's.
  """

  @behaviour RiotTakeHome.Cipher

  @impl true
  def encrypt(plaintext), do: Base.encode64(plaintext)

  @impl true
  def decrypt(data), do: Base.decode64(data)
end
