defmodule RiotTakeHome.Canonical do
  @moduledoc """
  Deterministic serialization of a decoded JSON term, used as signing input.

  This is close to RFC 8785 (JSON Canonicalization Scheme) and deviates from it
  on purpose in one place: numbers. RFC 8785 serializes numbers with the
  ECMAScript double-based algorithm, which collapses any integer beyond 2^53.
  For a signing input that is a security defect: `12345678901234567890` and
  `...891` produce the same canonical form under JCS, so they share a valid
  signature. This module keeps integers at their arbitrary precision instead,
  so those two sign differently. The accepted price is that `1` and `1.0` also
  sign differently, since neither is normalised through a float.

  Object keys are sorted at every depth. The sort is explicit because Erlang
  map iteration order above 32 entries depends on the runtime's internal
  hashing, which is not stable across OTP versions. It is bytewise over UTF-8
  rather than JCS's UTF-16 code units, which agrees with JCS for ASCII keys and
  can differ only for keys containing characters beyond U+FFFF. Array order is
  preserved: it is significant in JSON.
  """

  @spec encode(term()) :: binary()
  def encode(term), do: term |> to_iodata() |> IO.iodata_to_binary()

  defp to_iodata(map) when is_map(map) do
    entries =
      map
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.map_intersperse(",", fn {key, value} ->
        [JSON.encode_to_iodata!(key), ":", to_iodata(value)]
      end)

    ["{", entries, "}"]
  end

  defp to_iodata(list) when is_list(list) do
    ["[", Enum.map_intersperse(list, ",", &to_iodata/1), "]"]
  end

  defp to_iodata(scalar), do: JSON.encode_to_iodata!(scalar)
end
