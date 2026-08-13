defmodule RiotTakeHome.Bound do
  @moduledoc """
  The integer size bound, shared by the HTTP layer and the decrypt path.

  The body limit bounds bytes, not CPU. Turning a bignum back into decimal is
  quadratic in its length, and every endpoint re-encodes what it was given, so
  one 1 MB integer literal costs ~24 s where 1 MB of text costs 1 ms. Bounding
  the digits bounds the whole worst case: cost grows as body size times this
  limit, which puts a full 1 MiB body under 50 ms measured. A 1000-digit
  integer is about 3300 bits, past any real value, so exact arithmetic is
  untouched.

  The router applies the bound to the parsed request body, which only covers
  integers that appear literally in the JSON. A ciphertext hides its plaintext
  from that check, so the decrypt path applies the same predicate to every
  value it is about to emit: what the service accepts and what it produces are
  bounded by one rule, in one place.
  """

  @max_digits 1000
  @max_integer Integer.pow(10, @max_digits)

  @doc "The digit bound, exposed for error messages."
  @spec max_digits() :: pos_integer()
  def max_digits, do: @max_digits

  @doc "Whether every integer in the term stays under `max_digits/0` digits."
  @spec bounded?(term()) :: boolean()
  def bounded?(int) when is_integer(int), do: int < @max_integer and int > -@max_integer
  def bounded?(map) when is_map(map), do: Enum.all?(map, fn {_key, value} -> bounded?(value) end)
  def bounded?(list) when is_list(list), do: Enum.all?(list, &bounded?/1)
  def bounded?(_other), do: true
end
