defmodule RiotTakeHome.CanonicalTest do
  use ExUnit.Case, async: true

  alias RiotTakeHome.Canonical

  describe "encode/1" do
    test "objects equal up to key permutation share one canonical form, at every depth" do
      a = JSON.decode!(~s({"b":{"y":1,"x":2},"a":[1,{"d":4,"c":3}]}))
      b = JSON.decode!(~s({"a":[1,{"c":3,"d":4}],"b":{"x":2,"y":1}}))

      # Expected form written by hand: keys sorted bytewise at both depths,
      # including inside the object nested in the array.
      expected = ~s({"a":[1,{"c":3,"d":4}],"b":{"x":2,"y":1}})

      assert Canonical.encode(a) == expected
      assert Canonical.encode(b) == expected
    end

    test "array order is preserved because it is significant in JSON" do
      assert Canonical.encode([1, 2, 3]) == "[1,2,3]"
      assert Canonical.encode([3, 2, 1]) == "[3,2,1]"
      refute Canonical.encode([1, 2, 3]) == Canonical.encode([3, 2, 1])
    end

    # This test is the justification for the three lines of explicit sorting
    # in Canonical. Up to 32 entries an Erlang map is a flatmap and iterates
    # in term order, so a small map comes out sorted for free, which makes the
    # sort look unnecessary on any small example. Above 32 entries the map
    # switches to a hashed representation whose iteration order depends on the
    # runtime's internal hashing, which is not a stable contract across OTP
    # versions. Without the explicit sort, signatures could stop verifying
    # after an OTP upgrade.
    test "explicit sorting does real work above 32 keys" do
      keys = for i <- 1..40, do: "k" <> String.pad_leading(Integer.to_string(i), 2, "0")
      big = Map.new(Enum.with_index(keys, 1))

      # Natural iteration order of a 40-key map is NOT sorted...
      refute Map.keys(big) == Enum.sort(Map.keys(big))

      # ...while a 3-key flatmap comes out sorted all by itself.
      assert Map.keys(%{"c" => 3, "a" => 1, "b" => 2}) == ["a", "b", "c"]

      # The canonical form of the big map is nevertheless fully sorted.
      # Expected string is built with plain string concatenation from the
      # already-sorted key list, not with the function under test.
      expected =
        "{" <>
          Enum.map_join(Enum.with_index(keys, 1), ",", fn {key, i} -> ~s("#{key}":#{i}) end) <>
          "}"

      assert Canonical.encode(big) == expected
    end

    test "numbers are emitted exactly as decoded, without float normalisation" do
      assert Canonical.encode(%{"n" => 12_345_678_901_234_567_890}) ==
               ~s({"n":12345678901234567890})

      assert Canonical.encode(%{"n" => 1.5}) == ~s({"n":1.5})
      assert Canonical.encode(%{"n" => 1}) == ~s({"n":1})
    end
  end
end
