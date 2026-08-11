defmodule RiotTakeHome.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias RiotTakeHome.Canonical
  alias RiotTakeHome.Payload
  alias RiotTakeHome.Signer

  # Generators for arbitrary JSON trees. The scalar pool deliberately
  # includes huge integers (arbitrary precision must survive the round trip)
  # and raw UTF-8 strings, not just printable ones.
  #
  # One accepted limit: a PLAINTEXT
  # string that happens to be a well-formed marker of a known cipher (for
  # example the literal string "enc:b64:MzA" sent to /decrypt) is
  # indistinguishable from a ciphertext and will be decrypted. The
  # encrypt-then-decrypt round trip below is still exact for such strings,
  # since they are wrapped before being unwrapped, so the property holds
  # universally; only a decrypt-is-identity-on-plaintext property would not,
  # and none is claimed.

  defp json_string, do: one_of([string(:printable), string(:utf8)])

  defp big_integer do
    # far beyond 2^53: any pass through an IEEE-754 double would corrupt it
    map(integer(), fn n -> n + 12_345_678_901_234_567_890 end)
  end

  defp json_scalar do
    one_of([integer(), big_integer(), float(), boolean(), constant(nil), json_string()])
  end

  defp json_value do
    tree(json_scalar(), fn child ->
      one_of([list_of(child, max_length: 4), map_of(json_string(), child, max_length: 4)])
    end)
  end

  defp json_object, do: map_of(json_string(), json_value(), max_length: 8)

  # `==` would let a 1 that drifted into 1.0 pass unnoticed (Elixir compares
  # 1 == 1.0 as true, including inside maps): compare scalars with `===`.
  defp strict_equal?(a, b) when is_map(a) and is_map(b) do
    map_size(a) == map_size(b) and
      Enum.all?(a, fn {key, value} ->
        case Map.fetch(b, key) do
          {:ok, other} -> strict_equal?(value, other)
          :error -> false
        end
      end)
  end

  defp strict_equal?(a, b) when is_list(a) and is_list(b) do
    length(a) == length(b) and
      a |> Enum.zip(b) |> Enum.all?(fn {x, y} -> strict_equal?(x, y) end)
  end

  defp strict_equal?(a, b), do: a === b

  property "encrypt then decrypt restores the original object, types included" do
    check all(object <- json_object()) do
      round_tripped = object |> Payload.encrypt_payload() |> Payload.decrypt_payload()
      assert strict_equal?(round_tripped, object)
    end
  end

  property "the canonical form is independent of map construction order" do
    check all(object <- json_object()) do
      rebuilt = object |> Map.to_list() |> Enum.shuffle() |> Map.new()
      assert Canonical.encode(rebuilt) == Canonical.encode(object)
    end
  end

  property "the canonical form is valid JSON that decodes back to the same term" do
    # guards against key loss, escaping bugs and number corruption in one go
    check all(value <- json_value()) do
      assert strict_equal?(JSON.decode!(Canonical.encode(value)), value)
    end
  end

  property "sign then verify round-trips for arbitrary objects" do
    check all(object <- json_object()) do
      assert Signer.valid?(object, Signer.sign(object))
    end
  end
end
